import socket
import threading
import time
import uuid
import hashlib
import base64
import os
import sys
from collections import deque

# --- Constantes ---
DEFAULT_PORT = 55555
BROADCAST_ADDR = "255.255.255.255" # Ou o endereço de broadcast específico da rede
HEARTBEAT_INTERVAL = 5  # Segundos
DEVICE_TIMEOUT = 15     # Segundos (maior que 2 * HEARTBEAT_INTERVAL)
ACK_TIMEOUT = 5         # Segundos para esperar por um ACK
MAX_RETRIES = 3         # Máximo de retransmissões
CHUNK_SIZE = 512       # Tamanho do bloco de dados para CHUNK (bytes antes do base64)
MAX_MESSAGE_SIZE = 65507 # Tamanho máximo teórico do payload UDP

# --- Estruturas de Dados Globais (Protegidas por Locks) ---
active_devices = {}  # { 'nome': {'ip': str, 'port': int, 'last_heartbeat': float} }
pending_acks = {}    # { 'msg_id': {'target': (ip, port), 'message': bytes, 'timestamp': float, 'retries': int, 'callback': callable} }
ongoing_sends = {}   # { 'transfer_id': {'target_name': str, 'filepath': str, 'file_size': int, 'total_chunks': int, 'next_seq': int, 'file_hash': str, 'ack_received': bool} }
ongoing_receives = {} # { 'transfer_id': {'sender': (ip, port), 'filename': str, 'file_size': int, 'chunks': {seq: data}, 'total_chunks': None, 'file_handle': file, 'received_bytes': int} }
received_msg_ids = deque(maxlen=100) # Guarda IDs recentes para evitar duplicatas (exceto CHUNKs que têm sua própria lógica)

# Locks para proteger o acesso concorrente às estruturas de dados
devices_lock = threading.Lock()
acks_lock = threading.Lock()
sends_lock = threading.Lock()
receives_lock = threading.Lock()
received_ids_lock = threading.Lock()

# Flag para sinalizar o encerramento das threads
shutdown_flag = threading.Event()

# Nome do dispositivo (pode ser pego do hostname ou argumento)
DEVICE_NAME = socket.gethostname()

# --- Funções Auxiliares ---

def get_device_addr(device_name):
    """Retorna (ip, port) do dispositivo pelo nome, ou None se não encontrado."""
    with devices_lock:
        device_info = active_devices.get(device_name)
        if device_info:
            return (device_info['ip'], device_info['port'])
    return None

def create_message(command, *args):
    """Cria uma mensagem formatada como bytes."""
    message = f"{command}"
    for arg in args:
        message += f" {arg}"
    return message.encode('utf-8')

def parse_message(data, addr):
    """Decodifica e parseia a mensagem recebida."""
    try:
        message = data.decode('utf-8')
        parts = message.split(' ', 2) # Divide no máximo 2 vezes para pegar comando, id/nome, resto
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        return command, args, addr
    except Exception as e:
        print(f"[Erro] Falha ao parsear mensagem de {addr}: {e}", file=sys.stderr)
        return None, None, addr

def calculate_file_hash(filepath):
    """Calcula o hash SHA-256 de um arquivo."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(4096) # Ler em blocos para arquivos grandes
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[Erro] Falha ao calcular hash de {filepath}: {e}", file=sys.stderr)
        return None

def send_udp_message(sock, message_bytes, addr, needs_ack=False, msg_id=None, callback=None):
    """Envia uma mensagem UDP. Se needs_ack=True, registra para retransmissão."""
    try:
        sock.sendto(message_bytes, addr)
        # print(f"DEBUG: Enviado {message_bytes[:60]}... para {addr}") # Debug
        if needs_ack and msg_id:
            with acks_lock:
                pending_acks[msg_id] = {
                    'target': addr,
                    'message': message_bytes,
                    'timestamp': time.time(),
                    'retries': 0,
                    'callback': callback
                }
    except socket.error as e:
        print(f"[Erro] Falha ao enviar mensagem para {addr}: {e}", file=sys.stderr)
        # Se falhar ao enviar, chamar callback de falha imediatamente se houver
        if needs_ack and msg_id and callback:
            try:
                callback(msg_id, False, "Erro de socket ao enviar") # Falha
            except Exception as cb_e:
                print(f"[Erro] Callback de falha falhou: {cb_e}", file=sys.stderr)
    except Exception as e:
         print(f"[Erro] Erro inesperado ao enviar/registrar ACK: {e}", file=sys.stderr)


# --- Lógica do "Servidor" (Escuta e Resposta) ---

def handle_incoming_messages(sock):
    """Thread principal para receber e processar mensagens UDP."""
    print(f"[{DEVICE_NAME}] Ouvindo em UDP 0.0.0.0:{DEFAULT_PORT}")
    while not shutdown_flag.is_set():
        try:
            # Usar select para não bloquear indefinidamente e permitir shutdown
            ready, _, _ = select.select([sock], [], [], 0.5) # Timeout de 0.5s
            if ready:
                data, addr = sock.recvfrom(MAX_MESSAGE_SIZE)
                # print(f"DEBUG: Recebido {data[:60]}... de {addr}")

                command, args, sender_addr = parse_message(data, addr)
                if not command:
                    continue

                # Processar baseado no comando
                if command == "HEARTBEAT":
                    if len(args) >= 1:
                        handle_heartbeat(args[0], sender_addr)
                elif command == "TALK":
                    if len(args) >= 2:
                        msg_id = args[0]
                        content = args[1]
                        handle_talk(msg_id, content, sender_addr, sock)
                elif command == "FILE":
                    if len(args) >= 3:
                        msg_id = args[0]
                        filename = args[1]
                        try:
                            filesize = int(args[2])
                            handle_file(msg_id, filename, filesize, sender_addr, sock)
                        except ValueError:
                            print(f"[Aviso] Tamanho de arquivo inválido recebido de {sender_addr}: {args[2]}")
                            send_udp_message(sock, create_message("NACK", msg_id, "Tamanho inválido"), sender_addr)
                elif command == "CHUNK":
                     if len(args) >= 3:
                        msg_id = args[0] # ID da transferência, não da mensagem CHUNK em si
                        try:
                            seq = int(args[1])
                            data_b64 = args[2]
                            handle_chunk(msg_id, seq, data_b64, sender_addr, sock)
                        except ValueError:
                             print(f"[Aviso] Sequência CHUNK inválida recebida de {sender_addr}: {args[1]}")
                             # Não enviar NACK aqui, pois o remetente espera ACK do CHUNK específico
                        except IndexError:
                             print(f"[Aviso] Mensagem CHUNK mal formatada de {sender_addr}")
                elif command == "END":
                     if len(args) >= 2:
                        msg_id = args[0] # ID da transferência
                        file_hash = args[1]
                        handle_end(msg_id, file_hash, sender_addr, sock)
                elif command == "ACK":
                     if len(args) >= 1:
                        ack_id = args[0]
                        handle_ack(ack_id, sender_addr)
                elif command == "NACK":
                     if len(args) >= 2:
                        nack_id = args[0]
                        reason = args[1]
                        handle_nack(nack_id, reason, sender_addr)
                else:
                    print(f"[Aviso] Comando desconhecido '{command}' recebido de {sender_addr}")

        except socket.timeout:
            continue # Timeout é esperado por causa do select
        except Exception as e:
            if not shutdown_flag.is_set():
                 print(f"[Erro] Erro no loop de escuta: {e}", file=sys.stderr)
            time.sleep(0.1) # Evitar spam de erros

def handle_heartbeat(sender_name, sender_addr):
    """Processa uma mensagem HEARTBEAT."""
    if sender_name == DEVICE_NAME: # Ignorar próprio heartbeat
        return
    #print(f"DEBUG: Recebido HEARTBEAT de {sender_name} @ {sender_addr}")
    with devices_lock:
        now = time.time()
        active_devices[sender_name] = {
            'ip': sender_addr[0],
            'port': sender_addr[1],
            'last_heartbeat': now
        }

def handle_talk(msg_id, content, sender_addr, sock):
    """Processa uma mensagem TALK e envia ACK."""
    # Detecção de duplicata simples
    with received_ids_lock:
        if msg_id in received_msg_ids:
            print(f"[Aviso] Mensagem TALK duplicada {msg_id} de {sender_addr}, reenviando ACK.")
            ack_msg = create_message("ACK", msg_id)
            send_udp_message(sock, ack_msg, sender_addr)
            return
        received_msg_ids.append(msg_id)

    print(f"\n[Mensagem de {sender_addr[0]}]: {content}")
    # Enviar ACK
    ack_msg = create_message("ACK", msg_id)
    send_udp_message(sock, ack_msg, sender_addr)

def handle_file(msg_id, filename, filesize, sender_addr, sock):
    """Processa um pedido FILE, prepara para receber e envia ACK."""
    with received_ids_lock:
        if msg_id in received_msg_ids:
            print(f"[Aviso] Mensagem FILE duplicada {msg_id} de {sender_addr}, reenviando ACK.")
            ack_msg = create_message("ACK", msg_id)
            send_udp_message(sock, ack_msg, sender_addr)
            return
        received_msg_ids.append(msg_id)

    # Verifica se já existe uma transferência com esse ID (improvável, mas seguro)
    with receives_lock:
        if msg_id in ongoing_receives:
             print(f"[Aviso] Transferência FILE {msg_id} já em andamento. Ignorando duplicata.")
             # Reenvia ACK caso o remetente não tenha recebido
             ack_msg = create_message("ACK", msg_id)
             send_udp_message(sock, ack_msg, sender_addr)
             return

        # Criar arquivo temporário ou final? Vamos usar final com sufixo .part
        safe_filename = os.path.basename(filename) # Evitar path traversal
        local_filepath = f"{safe_filename}.part"
        try:
            file_handle = open(local_filepath, 'wb')
        except Exception as e:
             print(f"[Erro] Não foi possível criar o arquivo local {local_filepath}: {e}", file=sys.stderr)
             nack_msg = create_message("NACK", msg_id, f"Erro ao criar arquivo local: {e}")
             send_udp_message(sock, nack_msg, sender_addr)
             return

        total_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE if filesize > 0 else 1

        ongoing_receives[msg_id] = {
            'sender': sender_addr,
            'filename': safe_filename,
            'file_size': filesize,
            'chunks': {}, # Armazena chunks fora de ordem aqui {seq: data_bytes}
            'total_chunks': total_chunks,
            'next_expected_seq': 0,
            'file_handle': file_handle,
            'received_bytes': 0
        }
        print(f"\n[Transferência] Iniciando recebimento de '{safe_filename}' ({filesize} bytes) de {sender_addr[0]}. ID: {msg_id}")

    # Enviar ACK para FILE
    ack_msg = create_message("ACK", msg_id)
    send_udp_message(sock, ack_msg, sender_addr)

def handle_chunk(transfer_id, seq, data_b64, sender_addr, sock):
    """Processa uma mensagem CHUNK, armazena ou escreve, e envia ACK."""
    with receives_lock:
        transfer_info = ongoing_receives.get(transfer_id)
        if not transfer_info or transfer_info['sender'] != sender_addr:
            print(f"[Aviso] CHUNK recebido para transferência desconhecida ({transfer_id}) ou remetente errado ({sender_addr}). Ignorando.")
            # Não enviar NACK, pode ser pacote antigo/perdido
            return

        # Enviar ACK para o CHUNK *antes* de processar (confirma recebimento da mensagem)
        # Usar um ID único para o ACK do CHUNK para não confundir com o ACK do FILE/END
        chunk_ack_id = f"{transfer_id}-{seq}"
        ack_msg = create_message("ACK", chunk_ack_id) # ACK específico para este chunk
        send_udp_message(sock, ack_msg, sender_addr)

        # Detecção de CHUNK duplicado (já escrito ou na fila)
        if seq < transfer_info['next_expected_seq'] or seq in transfer_info['chunks']:
            print(f"[Aviso] CHUNK duplicado seq={seq} para {transfer_id}. Ignorando dados.")
            return # Já processamos ou temos na fila, mas o ACK foi reenviado acima

        # Decodificar dados
        try:
            chunk_data = base64.b64decode(data_b64)
        except Exception as e:
            print(f"[Erro] Falha ao decodificar base64 do CHUNK seq={seq} para {transfer_id}: {e}")
            # O remetente vai retransmitir se não receber o ACK específico do chunk
            return

        # Armazenar ou escrever?
        file_handle = transfer_info['file_handle']
        if seq == transfer_info['next_expected_seq']:
            # Chunk esperado, escrever diretamente
            try:
                file_handle.write(chunk_data)
                transfer_info['received_bytes'] += len(chunk_data)
                transfer_info['next_expected_seq'] += 1
                # Verificar se há chunks subsequentes na fila para escrever
                while transfer_info['next_expected_seq'] in transfer_info['chunks']:
                    next_seq = transfer_info['next_expected_seq']
                    queued_data = transfer_info['chunks'].pop(next_seq)
                    file_handle.write(queued_data)
                    transfer_info['received_bytes'] += len(queued_data)
                    transfer_info['next_expected_seq'] += 1
            except Exception as e:
                print(f"[Erro] Falha ao escrever CHUNK seq={seq} no arquivo {transfer_info['filename']}: {e}")
                # Limpeza pode ser necessária aqui ou no END/NACK
                # O remetente vai retransmitir, mas podemos ter problemas com o arquivo local
        elif seq > transfer_info['next_expected_seq']:
            # Chunk fora de ordem, armazenar temporariamente
            print(f"[Transferência] Recebido CHUNK fora de ordem seq={seq} (esperando {transfer_info['next_expected_seq']}) para {transfer_id}. Armazenando.")
            transfer_info['chunks'][seq] = chunk_data
        # else: seq < next_expected_seq (duplicado, já tratado)

        # Exibir progresso
        if transfer_info['file_size'] > 0:
             progress = (transfer_info['received_bytes'] / transfer_info['file_size']) * 100
             print(f"\r[Transferência {transfer_id}] Recebendo '{transfer_info['filename']}': {transfer_info['received_bytes']}/{transfer_info['file_size']} bytes ({progress:.2f}%)", end="")


def handle_end(transfer_id, received_hash, sender_addr, sock):
    """Processa a mensagem END, verifica o hash e envia ACK ou NACK."""
    with receives_lock:
        transfer_info = ongoing_receives.get(transfer_id)
        if not transfer_info or transfer_info['sender'] != sender_addr:
            print(f"[Aviso] END recebido para transferência desconhecida ({transfer_id}) ou remetente errado ({sender_addr}). Ignorando.")
            return

        # Fechar o arquivo para garantir que tudo foi escrito no disco
        file_handle = transfer_info['file_handle']
        local_filepath = file_handle.name
        file_handle.close()

        final_filename = transfer_info['filename']
        print(f"\n[Transferência {transfer_id}] Recebimento de '{final_filename}' concluído. Verificando integridade...")

        # Verificar se todos os chunks esperados foram recebidos (contagem ou tamanho)
        # next_expected_seq deve ser igual ao total_chunks
        all_chunks_received = (transfer_info['next_expected_seq'] == transfer_info['total_chunks'])
        size_matches = (transfer_info['received_bytes'] == transfer_info['file_size'])

        if not all_chunks_received or not size_matches:
             print(f"[Erro] Transferência {transfer_id} incompleta. Bytes: {transfer_info['received_bytes']}/{transfer_info['file_size']}, Chunks: {transfer_info['next_expected_seq']}/{transfer_info['total_chunks']}", file=sys.stderr)
             reason = "Transferência incompleta"
             nack_msg = create_message("NACK", transfer_id, reason)
             send_udp_message(sock, nack_msg, sender_addr)
             # Remover arquivo parcial e estado
             try:
                 os.remove(local_filepath)
             except OSError as e:
                 print(f"[Erro] Falha ao remover arquivo parcial {local_filepath}: {e}", file=sys.stderr)
             del ongoing_receives[transfer_id]
             return

        # Calcular hash local
        local_hash = calculate_file_hash(local_filepath)

        if local_hash and local_hash == received_hash:
            # Hash OK! Renomear arquivo e enviar ACK
            print(f"[Transferência {transfer_id}] Hash verificado com sucesso!")
            try:
                os.rename(local_filepath, final_filename)
                print(f"[Transferência {transfer_id}] Arquivo '{final_filename}' salvo.")
                ack_msg = create_message("ACK", transfer_id) # ACK para o END
                send_udp_message(sock, ack_msg, sender_addr)
            except OSError as e:
                print(f"[Erro] Falha ao renomear {local_filepath} para {final_filename}: {e}", file=sys.stderr)
                reason = f"Erro ao finalizar arquivo local: {e}"
                nack_msg = create_message("NACK", transfer_id, reason)
                send_udp_message(sock, nack_msg, sender_addr)
                # Tentar remover o .part se a renomeação falhou
                try: os.remove(local_filepath)
                except OSError: pass
        else:
            # Hash Falhou! Enviar NACK e remover arquivo
            print(f"[Erro] Falha na verificação de Hash para {transfer_id}!", file=sys.stderr)
            print(f"  Recebido: {received_hash}", file=sys.stderr)
            print(f"  Calculado: {local_hash}", file=sys.stderr)
            reason = "Falha na verificação de hash"
            nack_msg = create_message("NACK", transfer_id, reason)
            send_udp_message(sock, nack_msg, sender_addr)
            try:
                os.remove(local_filepath)
                print(f"[Transferência {transfer_id}] Arquivo corrompido '{local_filepath}' removido.")
            except OSError as e:
                print(f"[Erro] Falha ao remover arquivo corrompido {local_filepath}: {e}", file=sys.stderr)

        # Limpar estado da transferência
        if transfer_id in ongoing_receives:
           del ongoing_receives[transfer_id]


def handle_ack(ack_id, sender_addr):
    """Processa uma mensagem ACK, removendo a mensagem correspondente de pending_acks."""
    with acks_lock:
        pending_info = pending_acks.get(ack_id)
        if pending_info:
            # Verificar se o ACK veio do alvo esperado
            if pending_info['target'] == sender_addr or pending_info['target'][0] == BROADCAST_ADDR: # Aceitar ACK de qqr lugar se foi broadcast? Não faz sentido para ACKs. Melhor checar o target.
                 # print(f"DEBUG: Recebido ACK para {ack_id} de {sender_addr}")
                 callback = pending_info.get('callback')
                 del pending_acks[ack_id] # Remove da fila de espera

                 # Chamar callback de sucesso, se houver
                 if callback:
                     try:
                         callback(ack_id, True, None) # Sucesso
                     except Exception as e:
                         print(f"[Erro] Callback de sucesso para ACK {ack_id} falhou: {e}", file=sys.stderr)

            else:
                print(f"[Aviso] ACK para {ack_id} recebido de endereço inesperado {sender_addr} (esperado de {pending_info['target']}). Ignorando.")
        # else:
            # print(f"DEBUG: ACK recebido para msg_id {ack_id} não pendente ou já processado.")


def handle_nack(nack_id, reason, sender_addr):
    """Processa uma mensagem NACK."""
    print(f"\n[NACK Recebido] Mensagem/Transferência {nack_id} falhou. Motivo: {reason} (de {sender_addr[0]})")
    with acks_lock:
        pending_info = pending_acks.get(nack_id)
        if pending_info and pending_info['target'] == sender_addr:
            callback = pending_info.get('callback')
            del pending_acks[nack_id] # Remove da fila de espera

            # Chamar callback de falha, se houver
            if callback:
                try:
                    callback(nack_id, False, f"NACK recebido: {reason}") # Falha
                except Exception as e:
                     print(f"[Erro] Callback de NACK para {nack_id} falhou: {e}", file=sys.stderr)

    # Lógica adicional pode ser necessária dependendo do NACK
    # Por exemplo, limpar estado de transferência de arquivo se o NACK for para FILE ou END
    with sends_lock:
        if nack_id in ongoing_sends:
            print(f"[Transferência {nack_id}] Falha no envio de arquivo confirmada por NACK.")
            del ongoing_sends[nack_id]
            # Limpar ACKs pendentes relacionados a esta transferência (CHUNKS) pode ser complexo
            # Uma abordagem é o callback limpar os ACKs pendentes para os chunks dessa transferência

    with receives_lock:
        if nack_id in ongoing_receives:
            print(f"[Transferência {nack_id}] Falha no recebimento de arquivo confirmada por NACK (remoto).")
            transfer_info = ongoing_receives[nack_id]
            try:
                transfer_info['file_handle'].close()
                os.remove(transfer_info['file_handle'].name)
            except Exception as e:
                print(f"[Erro] Falha ao limpar arquivo parcial após NACK remoto: {e}", file=sys.stderr)
            del ongoing_receives[nack_id]


# --- Lógica Periódica (Heartbeat e Timeouts) ---

def send_heartbeat(sock):
    """Thread para enviar HEARTBEAT periodicamente via broadcast."""
    heartbeat_message = create_message("HEARTBEAT", DEVICE_NAME)
    print("[DEBUG] Heartbeat thread iniciada.")
    while not shutdown_flag.is_set():
        try:
            print(f"[DEBUG] Tentando enviar HEARTBEAT: {heartbeat_message.decode()}")
            sock.sendto(heartbeat_message, (BROADCAST_ADDR, DEFAULT_PORT))
            print(f"[DEBUG] HEARTBEAT enviado para {(BROADCAST_ADDR, DEFAULT_PORT)}")
        except socket.error as e:
             print(f"[Erro] Falha ao enviar HEARTBEAT: {e}", file=sys.stderr)
        except Exception as e:
             print(f"[Erro] Erro inesperado no envio de HEARTBEAT: {e}", file=sys.stderr)
        shutdown_flag.wait(HEARTBEAT_INTERVAL)

def check_timeouts(sock):
    """Thread para verificar timeouts de ACKs (retransmitir) e de dispositivos (remover)."""
    while not shutdown_flag.is_set():
        now = time.time()

        # 1. Verificar ACKs pendentes e retransmitir
        acks_to_remove = []
        acks_to_retry = []
        with acks_lock:
            for msg_id, info in pending_acks.items():
                if now - info['timestamp'] > ACK_TIMEOUT:
                    if info['retries'] < MAX_RETRIES:
                        # Retransmitir
                        info['retries'] += 1
                        info['timestamp'] = now
                        acks_to_retry.append((info['message'], info['target'], msg_id, info['retries']))
                        # print(f"DEBUG: Retransmitindo msg {msg_id} (tentativa {info['retries']}) para {info['target']}")
                    else:
                        # Máximo de retries atingido
                        acks_to_remove.append(msg_id)
                        print(f"\n[Erro] Timeout final: Nenhuma resposta para msg {msg_id} de {info['target']} após {MAX_RETRIES} tentativas.", file=sys.stderr)
                        # Chamar callback de falha
                        callback = info.get('callback')
                        if callback:
                             try:
                                 callback(msg_id, False, f"Timeout final após {MAX_RETRIES} retentativas") # Falha
                             except Exception as e:
                                 print(f"[Erro] Callback de timeout final para {msg_id} falhou: {e}", file=sys.stderr)

                        # Limpar estado de envio se for uma transferência de arquivo
                        with sends_lock:
                            if msg_id in ongoing_sends:
                                print(f"[Transferência {msg_id}] Falha no envio de arquivo devido a timeout.")
                                del ongoing_sends[msg_id]
                                # TODO: Idealmente, limpar ACKs pendentes de CHUNKs associados

        # Realizar retransmissões fora do lock
        for msg_bytes, target_addr, msg_id_retry, retry_count in acks_to_retry:
             print(f"\n[Retransmissão] Retransmitindo mensagem {msg_id_retry} (tentativa {retry_count+1}/{MAX_RETRIES+1}) para {target_addr}")
             send_udp_message(sock, msg_bytes, target_addr) # Não precisa de ACK aqui, já está sendo rastreado

        # Remover ACKs que falharam permanentemente
        if acks_to_remove:
            with acks_lock:
                for msg_id in acks_to_remove:
                    if msg_id in pending_acks: # Verifica se não foi removido por um NACK enquanto isso
                       del pending_acks[msg_id]

        # 2. Verificar dispositivos inativos
        check_inactive_devices_internal(now)

        # Esperar um pouco antes da próxima verificação
        shutdown_flag.wait(1.0) # Verificar a cada segundo

def check_inactive_devices_internal(current_time):
    """Lógica interna para remover dispositivos inativos (chamada com ou sem lock)."""
    inactive_threshold = current_time - DEVICE_TIMEOUT
    devices_to_remove = []
    # Precisa do lock aqui, pois pode ser chamada por handle_heartbeat ou check_timeouts
    with devices_lock:
        for name, info in active_devices.items():
            if info['last_heartbeat'] < inactive_threshold:
                devices_to_remove.append(name)

        for name in devices_to_remove:
            del active_devices[name]
            print(f"\n[Sistema] Dispositivo '{name}' removido por inatividade.")

# --- Lógica do "Cliente" (Comandos do Usuário) ---

def handle_user_commands(sock):
    print("\n--- Interface de Comandos ---")
    print("Comandos disponíveis:")
    print("  devices                      - Lista dispositivos ativos")
    print("  talk <nome> <mensagem>       - Envia mensagem de texto")
    print("  sendfile <nome> <arquivo>    - Envia um arquivo")
    print("  quit                         - Encerra o dispositivo")
    print("-----------------------------")

    while not shutdown_flag.is_set():
        try:
            cmd_line = input(f"{DEVICE_NAME}> ").strip()
            if not cmd_line:
                continue

            parts = cmd_line.split(' ', 2)
            command = parts[0].lower()

            if command == "quit":
                print("[Sistema] Encerrando...")
                shutdown_flag.set()
                break
            elif command == "devices":
                display_active_devices()
            elif command == "talk":
                if len(parts) == 3:
                    target_name = parts[1]
                    message_text = parts[2]
                    send_talk_message(sock, target_name, message_text)
                else:
                    print("Uso: talk <nome_dispositivo> <mensagem>")
            elif command == "sendfile":
                 if len(parts) == 3:
                    target_name = parts[1]
                    filepath = parts[2]
                    send_file(sock, target_name, filepath)
                 else:
                    print("Uso: sendfile <nome_dispositivo> <caminho_arquivo_local>")
            else:
                print(f"Comando desconhecido: {command}")

        except EOFError:
             print("\n[Sistema] EOF recebido, encerrando...")
             shutdown_flag.set()
             break
        except KeyboardInterrupt:
             print("\n[Sistema] Interrupção recebida, encerrando...")
             shutdown_flag.set()
             break
        except Exception as e:
             print(f"[Erro] Erro ao processar comando: {e}", file=sys.stderr)


def display_active_devices():
    """Exibe a lista de dispositivos ativos."""
    with devices_lock:
        if not active_devices:
            print("[Sistema] Nenhum outro dispositivo ativo detectado.")
            return
        print("\n--- Dispositivos Ativos ---")
        now = time.time()
        for name, info in active_devices.items():
            last_seen = now - info['last_heartbeat']
            print(f"  - Nome: {name}")
            print(f"    IP: {info['ip']}, Porta: {info['port']}")
            print(f"    Último contato: {last_seen:.1f} segundos atrás")
        print("---------------------------")

def talk_callback(msg_id, success, error_reason):
    """Callback para mensagens TALK."""
    if success:
        print(f"\n[Sistema] Mensagem {msg_id} entregue com sucesso.")
    else:
        print(f"\n[Erro] Falha ao entregar mensagem {msg_id}: {error_reason}", file=sys.stderr)

def send_talk_message(sock, target_name, message_text):
    """Envia uma mensagem TALK para um dispositivo específico."""
    target_addr = get_device_addr(target_name)
    print(f"DEBUG: Tentando enviar TALK para {target_name} no endereço {target_addr}")
    if not target_addr:
        print(f"[Erro] Dispositivo '{target_name}' não encontrado ou inativo.", file=sys.stderr)
        return

    msg_id = str(uuid.uuid4())
    message = create_message("TALK", msg_id, message_text)

    print(f"[Sistema] Enviando mensagem para {target_name}...")
    send_udp_message(sock, message, target_addr, needs_ack=True, msg_id=msg_id, callback=talk_callback)


# --- Lógica de Envio de Arquivo ---
def send_file(sock, target_name, filepath):
    """Inicia o processo de envio de arquivo."""
    target_addr = get_device_addr(target_name)
    if not target_addr:
        print(f"[Erro] Dispositivo '{target_name}' não encontrado ou inativo.", file=sys.stderr)
        return

    if not os.path.isfile(filepath):
        print(f"[Erro] Arquivo local não encontrado: {filepath}", file=sys.stderr)
        return

    try:
        file_size = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        file_hash = calculate_file_hash(filepath)
        if file_hash is None:
            print(f"[Erro] Não foi possível calcular o hash do arquivo: {filepath}", file=sys.stderr)
            return
    except Exception as e:
        print(f"[Erro] Falha ao obter informações do arquivo {filepath}: {e}", file=sys.stderr)
        return

    transfer_id = str(uuid.uuid4()) # ID único para toda a transferência
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if file_size > 0 else 1

    # Registrar estado da transferência
    with sends_lock:
        ongoing_sends[transfer_id] = {
            'target_name': target_name,
            'target_addr': target_addr,
            'filepath': filepath,
            'file_size': file_size,
            'total_chunks': total_chunks,
            'next_seq': 0,
            'file_hash': file_hash,
            'ack_received': threading.Event() # Evento para sinalizar ACK do FILE/END/NACK
        }

    # Criar e enviar mensagem FILE
    file_message = create_message("FILE", transfer_id, filename, str(file_size))
    print(f"[Transferência {transfer_id}] Iniciando envio de '{filename}' ({file_size} bytes) para {target_name}...")
    send_udp_message(sock, file_message, target_addr, needs_ack=True, msg_id=transfer_id, callback=file_transfer_callback)

    # A continuação (envio de CHUNKs) acontecerá no callback se o ACK do FILE for recebido.

def file_transfer_callback(msg_id, success, reason):
    """Callback para ACKs/NACKs/Timeouts de mensagens FILE, END e CHUNKs."""
    # Determinar se é um ACK/NACK para FILE, END ou CHUNK
    is_chunk_ack = '-' in msg_id # IDs de ACK de chunk são "transfer_id-seq"

    if is_chunk_ack:
        # Callback para ACK de CHUNK
        transfer_id, seq_str = msg_id.split('-', 1)
        try:
             seq = int(seq_str)
        except ValueError:
             print(f"[Erro] ID de ACK de CHUNK inválido: {msg_id}", file=sys.stderr)
             return

        with sends_lock:
             transfer_info = ongoing_sends.get(transfer_id)
             if not transfer_info:
                 # Transferência pode ter sido cancelada/concluída
                 # print(f"DEBUG: ACK de CHUNK {seq} para transferência {transfer_id} não encontrada.")
                 return

             if success:
                 # print(f"DEBUG: ACK recebido para CHUNK {seq} da transferência {transfer_id}")
                 # Verificar se este ACK permite enviar o próximo chunk
                 # A lógica de enviar o próximo chunk é melhor gerenciada após o envio inicial do FILE
                 # e continuada aqui.
                 if seq == transfer_info['next_seq'] - 1: # Confirmação do último enviado
                     # Se ainda há chunks a enviar, envia o próximo
                     if transfer_info['next_seq'] < transfer_info['total_chunks']:
                          send_next_chunk(transfer_id, transfer_info)
                     else:
                          # Todos os chunks enviados e último ACK recebido, enviar END
                          if not transfer_info.get('end_sent', False): # Evitar enviar END múltiplas vezes
                              send_end_message(transfer_id, transfer_info)
                 # else: ACK de chunk antigo ou fora de ordem, ignorar para controle de fluxo
             else:
                 # Falha ao receber ACK do CHUNK (timeout ou NACK implícito)
                 print(f"\n[Erro] Falha ao confirmar CHUNK {seq} para transferência {transfer_id}: {reason}", file=sys.stderr)
                 # Abortar a transferência? Ou confiar na retransmissão geral?
                 # Por segurança, vamos abortar aqui se um chunk falhar permanentemente
                 print(f"[Transferência {transfer_id}] Abortando envio devido à falha no CHUNK {seq}.")
                 if transfer_id in ongoing_sends:
                      del ongoing_sends[transfer_id]
                 # Limpar ACKs pendentes relacionados é complexo, a thread de timeout eventualmente fará isso.

    else: # Callback para FILE ou END (msg_id == transfer_id)
        transfer_id = msg_id
        with sends_lock:
            transfer_info = ongoing_sends.get(transfer_id)
            if not transfer_info:
                 # print(f"DEBUG: Callback para transferência {transfer_id} não encontrada (FILE/END).")
                 return # Transferência já concluída ou abortada

            if success:
                 # Determinar se foi ACK para FILE ou END
                 # Se next_seq == 0, foi ACK para FILE, iniciar envio de chunks
                 if transfer_info['next_seq'] == 0:
                     print(f"[Transferência {transfer_id}] Destinatário aceitou o arquivo. Iniciando envio dos blocos...")
                     send_next_chunk(transfer_id, transfer_info) # Envia o primeiro chunk
                 else:
                     # Foi ACK para END
                     print(f"\n[Transferência {transfer_id}] Arquivo '{os.path.basename(transfer_info['filepath'])}' enviado e confirmado com sucesso por {transfer_info['target_name']}!")
                     # Limpar estado da transferência
                     if transfer_id in ongoing_sends:
                          del ongoing_sends[transfer_id]

            else: # Falha no FILE ou END (NACK ou Timeout)
                 print(f"\n[Erro] Falha na transferência {transfer_id}: {reason}", file=sys.stderr)
                 # Limpar estado da transferência
                 if transfer_id in ongoing_sends:
                      del ongoing_sends[transfer_id]
                 # Limpar ACKs pendentes relacionados (se houver)


def send_next_chunk(transfer_id, transfer_info):
    """Lê e envia o próximo chunk do arquivo."""
    global sock # Precisa do socket global aqui

    seq = transfer_info['next_seq']
    filepath = transfer_info['filepath']
    target_addr = transfer_info['target_addr']

    try:
        with open(filepath, 'rb') as f:
            f.seek(seq * CHUNK_SIZE)
            chunk_data = f.read(CHUNK_SIZE)

        if not chunk_data and seq < transfer_info['total_chunks']:
            # Isso não deveria acontecer se o tamanho foi calculado corretamente
            print(f"[Erro] Falha ao ler chunk {seq} do arquivo {filepath}, embora esperado.", file=sys.stderr)
            # Abortar?
            with sends_lock:
                if transfer_id in ongoing_sends: del ongoing_sends[transfer_id]
            return

        if chunk_data:
            chunk_b64 = base64.b64encode(chunk_data).decode('utf-8')
            chunk_msg_id = f"{transfer_id}-{seq}" # ID único para o ACK deste chunk
            chunk_message = create_message("CHUNK", transfer_id, str(seq), chunk_b64)

            # Exibir progresso
            progress = ((seq + 1) / transfer_info['total_chunks']) * 100
            print(f"\r[Transferência {transfer_id}] Enviando chunk {seq+1}/{transfer_info['total_chunks']} ({progress:.1f}%)", end="")

            transfer_info['next_seq'] += 1 # Incrementa antes de enviar para evitar race condition no callback

            # Enviar CHUNK e esperar ACK específico para ele
            send_udp_message(sock, chunk_message, target_addr, needs_ack=True, msg_id=chunk_msg_id, callback=file_transfer_callback)

        # Se este era o último chunk a ser lido/enviado, a lógica de enviar END
        # será acionada no callback quando o ACK deste último chunk chegar.
        # OU se o arquivo for 0 bytes, enviar END imediatamente após ACK do FILE.
        elif seq == 0 and transfer_info['total_chunks'] <= 1: # Caso de arquivo 0 bytes ou erro
             if not transfer_info.get('end_sent', False):
                  send_end_message(transfer_id, transfer_info)


    except Exception as e:
        print(f"\n[Erro] Falha ao ler/enviar chunk {seq} do arquivo {filepath}: {e}", file=sys.stderr)
        # Abortar transferência
        with sends_lock:
             if transfer_id in ongoing_sends: del ongoing_sends[transfer_id]

def send_end_message(transfer_id, transfer_info):
    """Envia a mensagem END para finalizar a transferência."""
    global sock # Precisa do socket global aqui

    target_addr = transfer_info['target_addr']
    file_hash = transfer_info['file_hash']
    end_message = create_message("END", transfer_id, file_hash)

    print(f"\n[Transferência {transfer_id}] Todos os chunks enviados. Enviando mensagem END.")
    transfer_info['end_sent'] = True # Marcar que END foi enviado
    send_udp_message(sock, end_message, target_addr, needs_ack=True, msg_id=transfer_id, callback=file_transfer_callback)


# --- Função Principal e Inicialização ---

# Variável global para o socket principal
sock = None

def main():
    global sock
    global DEVICE_NAME

    # Permitir definir nome e porta via argumentos (opcional)
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
            if len(sys.argv) > 2:
                DEVICE_NAME = sys.argv[2]
        except ValueError:
            print(f"Aviso: Porta inválida '{sys.argv[1]}'. Usando porta padrão {DEFAULT_PORT}.")
        except IndexError:
            pass # Apenas porta fornecida

    # Configurar socket UDP
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Permitir reutilizar endereço rapidamente
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Permitir envio de broadcast
        sock.bind(('0.0.0.0', port)) # Escutar em todas as interfaces
        # sock.settimeout(1.0) # Definir timeout para recvfrom não bloquear indefinidamente - substituido por select
    except socket.error as e:
        print(f"[Erro Fatal] Falha ao criar ou vincular socket na porta {port}: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
         print(f"[Erro Fatal] Erro inesperado na configuração do socket: {e}", file=sys.stderr)
         sys.exit(1)

    print(f"--- Dispositivo '{DEVICE_NAME}' iniciado na porta {port} ---")

    # Importar select aqui, pois só é usado na thread de escuta
    global select
    import select

    # Criar e iniciar threads
    threads = []
    try:
        listener_thread = threading.Thread(target=handle_incoming_messages, args=(sock,), name="ListenerThread")
        heartbeat_thread = threading.Thread(target=send_heartbeat, args=(sock,), name="HeartbeatThread")
        timeout_thread = threading.Thread(target=check_timeouts, args=(sock,), name="TimeoutThread")
        cli_thread = threading.Thread(target=handle_user_commands, args=(sock,), name="CLIThread")

        threads = [listener_thread, heartbeat_thread, timeout_thread, cli_thread]

        for t in threads:
            t.start()

        # Enviar um HEARTBEAT inicial imediatamente após iniciar
        initial_heartbeat = create_message("HEARTBEAT", DEVICE_NAME)
        send_udp_message(sock, initial_heartbeat, (BROADCAST_ADDR, port))

        # Manter a thread principal viva esperando pelas outras (ou pelo shutdown)
        # cli_thread.join() # Espera a CLI terminar (com quit, Ctrl+C ou Ctrl+D)

        # Alternativamente, esperar pelo evento de shutdown'
        shutdown_flag.wait()


    except Exception as e:
         print(f"[Erro Fatal] Falha ao iniciar threads: {e}", file=sys.stderr)
         shutdown_flag.set() # Tenta sinalizar shutdown para outras threads se alguma iniciou
    finally:
        print("[Sistema] Iniciando processo de encerramento...")
        shutdown_flag.set() # Garantir que a flag está setada

        # Esperar as threads terminarem
        for t in threads:
             if t.is_alive():
                 try:
                    #print(f"DEBUG: Esperando thread {t.name} terminar...")
                    t.join(timeout=2.0) # Espera um pouco por cada thread
                    if t.is_alive():
                         print(f"[Aviso] Thread {t.name} não encerrou a tempo.")
                 except Exception as e:
                     print(f"[Erro] Erro ao esperar thread {t.name}: {e}")


        # Fechar o socket
        if sock:
            print("[Sistema] Fechando socket.")
            sock.close()

        # Limpar arquivos parciais restantes (se houver)
        with receives_lock:
            for transfer_id, info in ongoing_receives.items():
                 try:
                     print(f"[Sistema] Limpando arquivo parcial da transferência {transfer_id}...")
                     info['file_handle'].close()
                     os.remove(info['file_handle'].name)
                 except Exception as e:
                      print(f"[Erro] Falha ao limpar arquivo parcial {info.get('filename', '')}.part: {e}", file=sys.stderr)

        print(f"[Sistema] Dispositivo '{DEVICE_NAME}' encerrado.")

if __name__ == "__main__":
    main()