import os
import socket
from pathlib import Path
 
from secure_transfer_utils import load_private_key, open_receiver_payload, recv_secure_packet

HOST = os.getenv("RECEIVER_HOST", "0.0.0.0")
DATA_PORT = int(os.getenv("DATA_PORT", os.getenv("PORT", "6000")))
RECEIVER_PRIVATE_KEY = os.getenv("RECEIVER_PRIVATE_KEY", "keys/receiver_private.pem")
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "")
LOG_FILE = os.getenv("RECEIVER_LOG_FILE", "")


def receive_packet() -> bytes:
    """Listen for one sender connection and receive one Lab 8 secure packet."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(TIMEOUT)
        server.bind((HOST, DATA_PORT))
        server.listen(1)
        conn, addr = server.accept()

        with conn:
            conn.settimeout(TIMEOUT)
            print(f"[+] Đã nhận kết nối từ {addr[0]}:{addr[1]}")
            return recv_secure_packet(conn)


def main() -> None:
    lines = [f"[*] Receiver đang lắng nghe tại {HOST}:{DATA_PORT}"]
    print(lines[0])

    packet = receive_packet()
    receiver_private_key = load_private_key(RECEIVER_PRIVATE_KEY)
    plaintext, integrity_ok = open_receiver_payload(packet, receiver_private_key)

    message = plaintext.decode("utf-8", errors="replace")
    if integrity_ok:
        lines.append("[+] Dữ liệu nguyên vẹn: SHA-256 khớp.")
        print(lines[-1])
    else:
        lines.append("[-] Dữ liệu bị thay đổi hoặc giả mạo: SHA-256 không khớp.")
        print(lines[-1])

    lines.extend([
        "[+] Đã giải mã DES key bằng RSA private key của receiver.",
        "[+] Đã giải mã bản tin bằng DES-CBC.",
        f"[+] Bản tin gốc: {message}",
    ])
    print("[+] Đã giải mã DES key bằng RSA private key của receiver.")
    print("[+] Đã giải mã bản tin bằng DES-CBC.")
    print(f"[+] Bản tin gốc: {message}")

    if OUTPUT_FILE:
        Path(OUTPUT_FILE).write_bytes(plaintext)

    if LOG_FILE:
        Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(LOG_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
