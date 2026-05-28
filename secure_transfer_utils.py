import hashlib
import os
import struct
from pathlib import Path
from typing import Tuple

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

DES_BLOCK_SIZE = 8
DES_KEY_SIZE = 8
DES_IV_SIZE = 8
RSA_KEY_SIZE = 2048
LENGTH_HEADER_SIZE = 4
SHA256_DIGEST_SIZE = 32


def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# =========================
# DES HELPERS
# =========================

def generate_des_key() -> bytes:
    return os.urandom(DES_KEY_SIZE)


def generate_des_key_iv() -> Tuple[bytes, bytes]:
    return os.urandom(DES_KEY_SIZE), os.urandom(DES_IV_SIZE)


def validate_des_key_iv(des_key: bytes, iv: bytes) -> None:
    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("DES key phải dài đúng 8 byte.")

    if len(iv) != DES_IV_SIZE:
        raise ValueError("IV phải dài đúng 8 byte.")


def encrypt_des_cbc(
    plaintext: bytes,
    des_key: bytes | None = None,
    iv: bytes | None = None,
) -> Tuple[bytes, bytes, bytes]:

    if des_key is None or iv is None:
        des_key, iv = generate_des_key_iv()

    validate_des_key_iv(des_key, iv)

    cipher = DES.new(des_key, DES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext, DES_BLOCK_SIZE))

    return des_key, iv, iv + encrypted


def decrypt_des_cbc(des_key: bytes, ciphertext_with_iv: bytes) -> bytes:
    if len(ciphertext_with_iv) <= DES_IV_SIZE:
        raise ValueError("Ciphertext không hợp lệ.")

    iv = ciphertext_with_iv[:DES_IV_SIZE]
    ciphertext = ciphertext_with_iv[DES_IV_SIZE:]

    cipher = DES.new(des_key, DES.MODE_CBC, iv)

    return unpad(cipher.decrypt(ciphertext), DES_BLOCK_SIZE)


# alias cho CI
def des_encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    _, _, ciphertext = encrypt_des_cbc(plaintext, key, os.urandom(8))
    return ciphertext


def des_decrypt_cbc(key: bytes, ciphertext: bytes) -> bytes:
    return decrypt_des_cbc(key, ciphertext)


# =========================
# RSA HELPERS
# =========================

def generate_rsa_keypair(private_path: str | Path, public_path: str | Path):
    private_path = Path(private_path)
    public_path = Path(public_path)

    private_path.parent.mkdir(parents=True, exist_ok=True)

    key = RSA.generate(RSA_KEY_SIZE)

    private_path.write_bytes(key.export_key())
    public_path.write_bytes(key.publickey().export_key())


def load_public_key(path: str | Path):
    return RSA.import_key(Path(path).read_bytes())


def load_private_key(path: str | Path):
    return RSA.import_key(Path(path).read_bytes())


def encrypt_des_key_rsa(des_key: bytes, receiver_public_key) -> bytes:
    cipher = PKCS1_OAEP.new(receiver_public_key)
    return cipher.encrypt(des_key)


def decrypt_des_key_rsa(encrypted_des_key: bytes, receiver_private_key) -> bytes:
    cipher = PKCS1_OAEP.new(receiver_private_key)
    return cipher.decrypt(encrypted_des_key)


# =========================
# PACKET HELPERS
# =========================

def pack_length(data: bytes) -> bytes:
    return struct.pack("!I", len(data))


def parse_length_header(header: bytes) -> int:
    # SỬA LỖI: test_packet_rejects_invalid_header
    if len(header) != LENGTH_HEADER_SIZE:
        raise ValueError("Độ dài header không hợp lệ, phải đủ 4 bytes.")
    return struct.unpack("!I", header)[0]


def build_secure_packet(
    encrypted_des_key: bytes,
    ciphertext_with_iv: bytes,
    plaintext_hash: bytes,
) -> bytes:

    return (
        pack_length(encrypted_des_key)
        + encrypted_des_key
        + pack_length(ciphertext_with_iv)
        + ciphertext_with_iv
        + plaintext_hash
    )


def parse_secure_packet(packet: bytes):
    # SỬA LỖI: Kiểm tra xem packet tối thiểu phải chứa đủ 2 headers độ dài và 1 mã hash không
    if len(packet) < (LENGTH_HEADER_SIZE * 2 + SHA256_DIGEST_SIZE):
        raise ValueError("Gói tin quá ngắn, không đúng cấu trúc.")

    cursor = 0

    # Đọc key_len
    key_len = parse_length_header(
        packet[cursor:cursor + LENGTH_HEADER_SIZE]
    )
    cursor += LENGTH_HEADER_SIZE

    encrypted_des_key = packet[cursor:cursor + key_len]
    cursor += key_len

    # Đọc cipher_len
    cipher_len = parse_length_header(
        packet[cursor:cursor + LENGTH_HEADER_SIZE]
    )
    cursor += LENGTH_HEADER_SIZE

    ciphertext_with_iv = packet[cursor:cursor + cipher_len]
    cursor += cipher_len

    # Đọc plaintext_hash
    plaintext_hash = packet[cursor:cursor + SHA256_DIGEST_SIZE]
    
    # SỬA LỖI: test_packet_rejects_wrong_hash_size
    # Kiểm tra xem phần hash còn lại thu được có chính xác bằng SHA256_DIGEST_SIZE không
    if len(plaintext_hash) != SHA256_DIGEST_SIZE:
        raise ValueError("Kích thước mã băm (hash) không hợp lệ.")
        
    cursor += SHA256_DIGEST_SIZE

    # SỬA LỖI: test_packet_rejects_extra_bytes
    # Nếu sau khi đọc hết mã băm mà cursor vẫn chưa đi hết chiều dài packet thực tế -> có dữ liệu thừa
    if cursor != len(packet):
        raise ValueError("Phát hiện gói tin có chứa dữ liệu thừa ở cuối.")

    return encrypted_des_key, ciphertext_with_iv, plaintext_hash


# =========================
# SENDER / RECEIVER
# =========================

def build_sender_payload(
    plaintext: bytes,
    receiver_public_key,
):

    plaintext_hash = sha256_digest(plaintext)

    des_key, _, ciphertext_with_iv = encrypt_des_cbc(plaintext)

    encrypted_des_key = encrypt_des_key_rsa(
        des_key,
        receiver_public_key,
    )

    packet = build_secure_packet(
        encrypted_des_key,
        ciphertext_with_iv,
        plaintext_hash,
    )

    return packet, des_key, ciphertext_with_iv, plaintext_hash


def open_receiver_payload(packet: bytes, receiver_private_key):

    encrypted_des_key, ciphertext_with_iv, received_hash = (
        parse_secure_packet(packet)
    )

    des_key = decrypt_des_key_rsa(
        encrypted_des_key,
        receiver_private_key,
    )

    plaintext = decrypt_des_cbc(
        des_key,
        ciphertext_with_iv,
    )

    calculated_hash = sha256_digest(plaintext)

    return plaintext, calculated_hash == received_hash


# =========================
# SOCKET HELPERS
# =========================

def recv_exact(conn, n: int) -> bytes:
    # SỬA LỖI: test_recv_exact_rejects_invalid_size
    if n <= 0:
        raise ValueError("Kích thước bytes cần nhận phải lớn hơn 0.")

    chunks = []
    received = 0

    while received < n:
        chunk = conn.recv(n - received)

        if not chunk:
            raise ConnectionError("Socket closed.")

        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)


def recv_secure_packet(conn) -> bytes:

    key_len_header = recv_exact(conn, LENGTH_HEADER_SIZE)

    key_len = parse_length_header(key_len_header)

    encrypted_des_key = recv_exact(conn, key_len)

    cipher_len_header = recv_exact(conn, LENGTH_HEADER_SIZE)

    cipher_len = parse_length_header(cipher_len_header)

    ciphertext_with_iv = recv_exact(conn, cipher_len)

    plaintext_hash = recv_exact(conn, SHA256_DIGEST_SIZE)

    return (
        key_len_header
        + encrypted_des_key
        + cipher_len_header
        + ciphertext_with_iv
        + plaintext_hash
    )
