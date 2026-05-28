import os
from pathlib import Path

from secure_transfer_utils import generate_rsa_keypair

PRIVATE_KEY_PATH = Path(os.getenv("RECEIVER_PRIVATE_KEY", "keys/receiver_private.pem"))
PUBLIC_KEY_PATH = Path(os.getenv("RECEIVER_PUBLIC_KEY", "keys/receiver_public.pem"))

 
def main() -> None:
    generate_rsa_keypair(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    print(f"[+] Đã tạo khóa riêng: {PRIVATE_KEY_PATH}")
    print(f"[+] Đã tạo khóa công khai: {PUBLIC_KEY_PATH}")
    print("[!] Chỉ chia sẻ receiver_public.pem cho Sender. Không commit private key thật lên GitHub.")


if __name__ == "__main__":
    main()
