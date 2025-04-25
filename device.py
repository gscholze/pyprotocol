from __future__ import annotations

import base64
import hashlib
import io
import os
import select
import socket
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from typing import (
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    TypedDict,
    TypeAlias,
)

DEFAULT_PORT = 55_555
BROADCAST_ADDR = "255.255.255.255"
HEARTBEAT_INTERVAL = 5  # seconds
DEVICE_TIMEOUT = 3 * HEARTBEAT_INTERVAL
ACK_TIMEOUT = 5  # seconds before retrying a message
MAX_RETRIES = 3  # retransmissions before giving up
CHUNK_SIZE = 512  # raw bytes per file chunk (before base64)
MAX_UDP_PAYLOAD = 65_507  # theoretical limit for IPv4
DEVICE_NAME = socket.gethostname()

CallbackType: TypeAlias = Optional[Callable[[str, bool, Optional[str]], None]]


class ActiveDeviceInfo(TypedDict):
    ip: str
    port: int
    last: float


class PendingAckInfo(TypedDict):
    target: Tuple[str, int]
    payload: bytes
    timestamp: float
    retries: int
    callback: CallbackType


class OngoingSendInfo(TypedDict):
    path: Path
    addr: Tuple[str, int]
    size: int
    chunks: int
    next_seq: int
    hash: str
    end_sent: bool


class OngoingReceiveInfo(TypedDict):
    sender: Tuple[str, int]
    filename: str
    size: int
    next_seq: int
    total_chunks: int
    chunks: Dict[int, bytes]
    fh: io.BufferedWriter
    received: int


active_devices: Dict[str, ActiveDeviceInfo] = {}
pending_acks: Dict[str, PendingAckInfo] = {}
ongoing_sends: Dict[str, OngoingSendInfo] = {}
ongoing_receives: Dict[str, OngoingReceiveInfo] = {}
received_msg_ids: deque[str] = deque(maxlen=100)  # de‑duplication window

devices_lock = threading.Lock()
acks_lock = threading.Lock()
sends_lock = threading.Lock()
receives_lock = threading.Lock()
received_ids_lock = threading.Lock()

shutdown_flag = threading.Event()

sock: socket.socket


def get_device_addr(name: str) -> Optional[Tuple[str, int]]:
    """Return (ip, port) of a peer by name or None if unknown/inactive."""
    with devices_lock:
        info = active_devices.get(name)
        return (info["ip"], info["port"]) if info else None


def create_message(cmd: str, *args: object) -> bytes:
    """Build a space‑separated UTF‑8 message ready for sendto."""
    return f"{cmd} {' '.join(map(str, args))}".encode()


def parse_message(
    data: bytes, addr: Tuple[str, int]
) -> Tuple[str, List[str], Tuple[str, int]]:
    """Decode raw UDP payload into (command, args, sender_addr)."""
    try:
        text = data.decode()
        parts = text.split(" ", 2)
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        return cmd, args, addr
    except UnicodeDecodeError:
        print(f"[Aviso] mensagem inválida de {addr}")
        return "", [], addr


def file_sha256(path: os.PathLike[str] | str) -> Optional[str]:
    """Return SHA‑256 hex digest of *path* or None on error."""
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError as exc:
        print(f"[Erro] Falha ao calcular hash de {path}: {exc}", file=sys.stderr)
        return None


def send_udp(
    sock_param: socket.socket,
    payload: bytes,
    target: Tuple[str, int],
    *,
    needs_ack: bool = False,
    msg_id: str | None = None,
    cb: CallbackType = None,
) -> None:
    """Send *payload* and optionally register it in *pending_acks*."""
    try:
        sock_param.sendto(payload, target)
        if needs_ack and msg_id:
            with acks_lock:
                pending_acks[msg_id] = {
                    "target": target,
                    "payload": payload,
                    "timestamp": time.time(),
                    "retries": 0,
                    "callback": cb,
                }
    except OSError as exc:
        print(f"[Erro] Falha ao enviar para {target}: {exc}", file=sys.stderr)
        if needs_ack and msg_id and cb:
            cb(msg_id, False, "erro de socket")


def listener(sock_param: socket.socket) -> None:
    print(f"[{DEVICE_NAME}] ouvindo em 0.0.0.0:{sock_param.getsockname()[1]}")

    while not shutdown_flag.is_set():
        ready, _, _ = select.select([sock_param], [], [], 0.5)
        if not ready:
            continue
        data, addr = sock_param.recvfrom(MAX_UDP_PAYLOAD)
        cmd, args, sender = parse_message(data, addr)
        if not cmd:
            continue
        if cmd == "HEARTBEAT" and args:
            handle_heartbeat(args[0], sender)
        elif cmd == "TALK" and len(args) >= 2:
            handle_talk(args[0], " ".join(args[1:]), sender, sock_param)
        elif cmd == "FILE" and len(args) >= 2:
            handle_incoming_file(args[0], " ".join(args[1:]), sender, sock_param)
        elif cmd == "CHUNK" and len(args) == 2:
            try:
                tid = args[0]
                seq_str, b64_data = args[1].split(" ", 1)
                seq = int(seq_str)
                handle_chunk(tid, seq, b64_data, sender, sock_param)
            except (ValueError, IndexError):
                print(f"[Aviso] formato inválido de CHUNK de {sender}: {args}")
        elif cmd == "END" and len(args) >= 2:
            handle_end(args[0], args[1], sender, sock_param)
        elif cmd == "ACK" and args:
            handle_ack(args[0], sender)
        elif cmd == "NACK" and len(args) >= 2:
            handle_nack(args[0], args[1], sender)
        else:
            print(f"[Warn] comando desconhecido '{cmd}' de {sender}")


def handle_heartbeat(name: str, sender: Tuple[str, int]) -> None:
    if name == DEVICE_NAME:
        return
    with devices_lock:
        active_devices[name] = {
            "ip": sender[0],
            "port": sender[1],
            "last": time.time(),
        }


def heartbeat_sender(sock_param: socket.socket) -> None:
    payload = create_message("HEARTBEAT", DEVICE_NAME)
    while not shutdown_flag.is_set():
        try:
            sock_param.sendto(payload, (BROADCAST_ADDR, DEFAULT_PORT))
        except OSError as exc:
            print(f"[Erro] heartbeat: {exc}", file=sys.stderr)
        shutdown_flag.wait(HEARTBEAT_INTERVAL)


def handle_talk(
    msg_id: str,
    text: str,
    sender: Tuple[str, int],
    sock_param: socket.socket,
) -> None:
    with received_ids_lock:
        if msg_id in received_msg_ids:
            send_udp(sock_param, create_message("ACK", msg_id), sender)
            return
        received_msg_ids.append(msg_id)

    print(f"\n[{sender[0]}] {text}")
    send_udp(sock_param, create_message("ACK", msg_id), sender)


def handle_incoming_file(
    msg_id: str,
    rest: str,
    sender: Tuple[str, int],
    sock_param: socket.socket,
) -> None:
    """Prepare to receive a file; reply with ACK so the sender starts CHUNKs."""
    try:
        filename, size_str = rest.rsplit(" ", 1)
        filesize = int(size_str)
    except ValueError:
        send_udp(sock_param, create_message("NACK", msg_id, "tamanho inválido"), sender)
        return

    with received_ids_lock:
        if msg_id in received_msg_ids:
            send_udp(sock_param, create_message("ACK", msg_id), sender)
            return
        received_msg_ids.append(msg_id)
    safe_filename = Path(filename).name
    temp_path = safe_filename + ".part"
    fh: Optional[io.BufferedWriter] = None
    try:
        fh = open(temp_path, "wb")
    except OSError as exc:
        send_udp(
            sock_param, create_message("NACK", msg_id, f"erro local: {exc}"), sender
        )
        return
    assert fh is not None

    total_chunks = max(1, (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE)
    with receives_lock:
        ongoing_receives[msg_id] = {
            "sender": sender,
            "filename": safe_filename,
            "size": filesize,
            "next_seq": 0,
            "total_chunks": total_chunks,
            "chunks": {},
            "fh": fh,
            "received": 0,
        }
    print(
        f"\n[Transfer] recebendo '{safe_filename}' ({filesize} B) de {sender[0]} — id={msg_id}"
    )
    send_udp(sock_param, create_message("ACK", msg_id), sender)


def handle_chunk(
    transfer_id: str,
    seq: int,
    b64: str,
    sender: Tuple[str, int],
    sock_param: socket.socket,
) -> None:
    with receives_lock:
        info = ongoing_receives.get(transfer_id)
        if not info or info["sender"] != sender:
            return
        send_udp(sock_param, create_message("ACK", f"{transfer_id}-{seq}"), sender)
        if seq < info["next_seq"] or seq in info["chunks"]:
            return

        try:
            data = base64.b64decode(b64)
        except base64.binascii.Error:
            return

        if seq == info["next_seq"]:
            info["fh"].write(data)
            info["received"] += len(data)
            info["next_seq"] += 1
            while info["next_seq"] in info["chunks"]:
                queued_data = info["chunks"].pop(info["next_seq"])
                info["fh"].write(queued_data)
                info["received"] += len(queued_data)
                info["next_seq"] += 1
        else:
            info["chunks"][seq] = data

        if info["size"] > 0:
            pct = info["received"] * 100 / info["size"]
            print(
                f"\r[Transfer {transfer_id}] {info['received']}/{info['size']} B"
                f" ({pct:.1f} %)",
                end="",
            )
        else:
            print(
                f"\r[Transfer {transfer_id}] {info['received']}/0 B (100.0 %)",
                end="",
            )


def handle_end(
    transfer_id: str,
    remote_hash: str,
    sender: Tuple[str, int],
    sock_param: socket.socket,
) -> None:
    info: Optional[OngoingReceiveInfo] = None
    with receives_lock:
        info = ongoing_receives.get(transfer_id)
        if not info or info["sender"] != sender:
            return
        info["fh"].close()
    if info is None:
        return

    print(f"\n[Transfer {transfer_id}] verificando integridade...")
    local_path = Path(info["filename"] + ".part")

    local_hash = file_sha256(local_path)
    ok = (
        info["next_seq"] == info["total_chunks"]
        and info["received"] == info["size"]
        and local_hash is not None
        and local_hash == remote_hash
    )

    if ok:
        final_name = info["filename"]
        try:
            local_path.replace(final_name)
            send_udp(sock_param, create_message("ACK", transfer_id), sender)
            print(f"[Transfer {transfer_id}] concluída: {final_name}")
        except OSError as e:
            print(f"[Erro] Falha ao renomear {local_path} para {final_name}: {e}")
            send_udp(
                sock_param,
                create_message("NACK", transfer_id, f"erro ao finalizar: {e}"),
                sender,
            )
            local_path.unlink(missing_ok=True)

    else:
        send_udp(
            sock_param,
            create_message("NACK", transfer_id, "hash ou tamanho incorreto"),
            sender,
        )
        local_path.unlink(missing_ok=True)
        print(f"[Erro] transferência {transfer_id} falhou — ficheiro removido")

    with receives_lock:
        ongoing_receives.pop(transfer_id, None)


def handle_ack(msg_id: str, sender: Tuple[str, int]) -> None:
    with acks_lock:
        info = pending_acks.pop(msg_id, None)

    if info and (info["target"] == sender or info["target"][0] == BROADCAST_ADDR):
        if cb := info.get("callback"):
            cb(msg_id, True, None)


def handle_nack(msg_id: str, reason: str, sender: Tuple[str, int]) -> None:
    print(f"\n[NACK] {msg_id} de {sender[0]}: {reason}")
    with acks_lock:
        info = pending_acks.pop(msg_id, None)

    if info and (cb := info.get("callback")):
        cb(msg_id, False, f"nack: {reason}")


def retry_manager(sock_param: socket.socket) -> None:
    while not shutdown_flag.is_set():
        now = time.time()

        to_retry: list[tuple[bytes, Tuple[str, int], str, int]] = []
        to_drop: list[str] = []

        with acks_lock:
            for mid, info in list(pending_acks.items()):
                if now - info["timestamp"] > ACK_TIMEOUT:
                    if info["retries"] < MAX_RETRIES:
                        info["retries"] += 1
                        info["timestamp"] = now
                        to_retry.append(
                            (info["payload"], info["target"], mid, info["retries"])
                        )
                    else:
                        to_drop.append(mid)
                        if cb := info.get("callback"):
                            cb(mid, False, "timeout final")

        for payload, target, mid, n in to_retry:
            print(f"\n[Retry] {mid} tent.{n}/{MAX_RETRIES} → {target}")
            send_udp(sock_param, payload, target)

        for mid in to_drop:
            with acks_lock:
                pending_acks.pop(mid, None)
            with sends_lock:
                if mid in ongoing_sends:
                    print(f"\n[Info] Transferência {mid} cancelada (timeout)")
                    ongoing_sends.pop(mid, None)
        purge_inactive_devices(now)
        shutdown_flag.wait(1.0)


def purge_inactive_devices(ts: float) -> None:
    dead: list[str] = []
    with devices_lock:
        for name, info in active_devices.items():
            if ts - info["last"] > DEVICE_TIMEOUT:
                dead.append(name)
        for name in dead:
            active_devices.pop(name, None)
            print(f"\n[Info] dispositivo '{name}' removido (timeout)")


def talk_callback(msg_id: str, ok: bool, error: Optional[str]) -> None:
    if ok:
        print(f"\n[Info] mensagem {msg_id} entregue")
    else:
        print(f"\n[Erro] mensagem {msg_id} falhou: {error}")


def send_talk(sock_param: socket.socket, target: str, text: str) -> None:
    addr = get_device_addr(target)
    if not addr:
        print(f"[Erro] '{target}' não encontrado")
        return
    mid = str(uuid.uuid4())
    send_udp(
        sock_param,
        create_message("TALK", mid, text),
        addr,
        needs_ack=True,
        msg_id=mid,
        cb=talk_callback,
    )


def send_file(
    sock_param: socket.socket, target: str, path_str: str | os.PathLike[str]
) -> None:
    addr = get_device_addr(target)
    if not addr:
        print(f"[Erro] '{target}' não encontrado")
        return

    try:
        size = os.path.getsize(path_str)
    except OSError as exc:
        print(f"[Erro] ficheiro: {exc}")
        return

    hsum = file_sha256(path_str)
    if not hsum:
        return

    filepath = Path(path_str)
    tid = str(uuid.uuid4())
    total_chunks = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)

    with sends_lock:
        ongoing_sends[tid] = {
            "path": filepath,
            "addr": addr,
            "size": size,
            "chunks": total_chunks,
            "next_seq": 0,
            "hash": hsum,
            "end_sent": False,
        }

    print(f"[Transfer {tid}] enviando '{filepath.name}' ({size} B) → {target}")
    send_udp(
        sock_param,
        create_message("FILE", tid, filepath.name, size),
        addr,
        needs_ack=True,
        msg_id=tid,
        cb=file_callback,
    )


def file_callback(tid_or_chunkid: str, ok: bool, reason: Optional[str]) -> None:
    base_id, sep, tail = tid_or_chunkid.rpartition("-")
    is_chunk_ack = bool(sep and tail.isdigit())

    if is_chunk_ack:
        tid, seq_str = base_id, tail
        seq = int(seq_str)
        with sends_lock:
            info = ongoing_sends.get(tid)
            if not info:
                return

            if ok:
                if seq == info["next_seq"] - 1:
                    if info["next_seq"] < info["chunks"]:
                        send_next_chunk(tid, info)
                    elif not info["end_sent"]:
                        send_end(tid, info)
            else:
                print(f"\n[Erro] CHUNK {seq} falhou ({tid}): {reason}")
                ongoing_sends.pop(tid, None)
        return

    else:
        tid = tid_or_chunkid
        with sends_lock:
            info = ongoing_sends.get(tid)
            if not info:
                return

            if ok:
                if info["next_seq"] == 0:
                    print(f"\n[Transfer {tid}] destinatário pronto, enviando chunks…")
                    send_next_chunk(tid, info)
                else:
                    print(f"\n[Transfer {tid}] concluída e confirmada!")
                    ongoing_sends.pop(tid, None)
            else:
                print(f"\n[Erro] transferência {tid} falhou: {reason}")
                ongoing_sends.pop(tid, None)


def send_next_chunk(tid: str, info: OngoingSendInfo) -> None:
    global sock
    seq = info["next_seq"]

    try:
        with open(info["path"], "rb") as fh:
            fh.seek(seq * CHUNK_SIZE)
            data = fh.read(CHUNK_SIZE)
    except OSError as e:
        print(f"\n[Erro] Falha ao ler chunk {seq} do ficheiro {info['path']}: {e}")
        with sends_lock:
            ongoing_sends.pop(tid, None)
        return

    if not data:
        print(f"\n[Aviso] Tentativa de ler chunk vazio {seq} para {tid}. Finalizando.")
        if not info["end_sent"]:
            send_end(tid, info)
        return

    b64 = base64.b64encode(data).decode()
    payload = create_message("CHUNK", tid, seq, b64)
    pct = (seq + 1) * 100 / info["chunks"]
    print(f"\r[Transfer {tid}] chunk {seq + 1}/{info['chunks']} ({pct:.1f} %)", end="")
    info["next_seq"] += 1

    send_udp(
        sock,
        payload,
        info["addr"],
        needs_ack=True,
        msg_id=f"{tid}-{seq}",
        cb=file_callback,
    )


def send_end(tid: str, info: OngoingSendInfo) -> None:
    global sock
    info["end_sent"] = True
    print(f"\n[Transfer {tid}] Todos os chunks enviados. Enviando END.")

    send_udp(
        sock,
        create_message("END", tid, info["hash"]),
        info["addr"],
        needs_ack=True,
        msg_id=tid,
        cb=file_callback,
    )


def cli(sock_param: socket.socket) -> None:
    print("\nComandos: devices | talk <peer> <msg> | sendfile <peer> <path> | quit")
    while not shutdown_flag.is_set():
        try:
            cmd_line = input(f"{DEVICE_NAME}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSaindo por interrupção...")
            shutdown_flag.set()
            break
        except Exception as e:
            print(f"\nErro no input: {e}")
            continue

        if not cmd_line:
            continue
        parts = cmd_line.split(" ", 2)
        cmd = parts[0].lower()

        match cmd:
            case "quit":
                shutdown_flag.set()
            case "devices":
                show_devices()
            case "talk" if len(parts) == 3:
                send_talk(sock_param, parts[1], parts[2])
            case "sendfile" if len(parts) == 3:
                send_file(sock_param, parts[1], parts[2])
            case _:
                print(f"Comando inválido ou argumentos incorretos: '{cmd_line}'")
                print(
                    "Uso: devices | talk <peer> <msg> | sendfile <peer> <path> | quit"
                )


def show_devices() -> None:
    with devices_lock:
        if not active_devices:
            print("(nenhum dispositivo)")
            return
        now = time.time()
        print("Dispositivos ativos:")
        for name, info in active_devices.items():
            print(
                f"• {name} — {info['ip']}:{info['port']} | "
                f"visto há {now - info['last']:.1f}s",
            )


def main() -> None:
    global sock, DEVICE_NAME

    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
            if not (1024 <= port <= 65535):
                raise ValueError("Porta fora do intervalo válido (1024-65535)")
            if len(sys.argv) > 2:
                DEVICE_NAME = sys.argv[2]
        except ValueError as e:
            print(f"Argumento inválido: {e}. Usando porta padrão {DEFAULT_PORT}.")
            port = DEFAULT_PORT

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", port))
    except OSError as e:
        print(f"Erro ao iniciar o socket na porta {port}: {e}", file=sys.stderr)
        print("Verifique se a porta já está em uso ou se há permissões.")
        sys.exit(1)

    print(f"--- {DEVICE_NAME} iniciado na porta {port} ---")

    threads = [
        threading.Thread(target=listener, args=(sock,), daemon=True),
        threading.Thread(target=heartbeat_sender, args=(sock,), daemon=True),
        threading.Thread(target=retry_manager, args=(sock,), daemon=True),
        threading.Thread(target=cli, args=(sock,), daemon=True),
    ]

    for t in threads:
        t.start()

    send_udp(sock, create_message("HEARTBEAT", DEVICE_NAME), (BROADCAST_ADDR, port))

    try:
        while not shutdown_flag.wait(0.5):
            pass
    except KeyboardInterrupt:
        print("\nEncerrando por KeyboardInterrupt...")
        shutdown_flag.set()
    finally:
        print("Encerrando threads e limpando...")
        if "sock" in globals() and sock:
            sock.close()

        with receives_lock:
            if ongoing_receives:
                print("Limpando transferências parciais...")
                for tid, info in list(ongoing_receives.items()):
                    try:
                        if not info["fh"].closed:
                            info["fh"].close()
                        partial_file = Path(info["filename"] + ".part")
                        partial_file.unlink(missing_ok=True)
                        print(f" - Removido {partial_file.name} (ID: {tid})")
                    except Exception as e:
                        print(f"Erro ao limpar {tid}: {e}")
        print("Programa finalizado.")


if __name__ == "__main__":
    main()
