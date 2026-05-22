import pytest
from Crypto.PublicKey import RSA

from secure_transfer_utils import (
    decrypt_des_cbc,
    decrypt_des_key_rsa,
    encrypt_des_cbc,
    encrypt_des_key_rsa,
    generate_des_key_iv,
    open_receiver_payload,
    build_sender_payload,
    sha256_digest,
)


def test_des_cbc_roundtrip():
    plaintext = "Xin chào FIT4012 - truyền dữ liệu an toàn".encode("utf-8")

    des_key, iv = generate_des_key_iv()

    _, _, ciphertext = encrypt_des_cbc(
        plaintext,
        des_key,
        iv,
    )

    assert ciphertext[:8] == iv

    decrypted = decrypt_des_cbc(
        des_key,
        ciphertext,
    )

    assert decrypted == plaintext


def test_des_rejects_wrong_key_size():
    with pytest.raises(ValueError):
        decrypt_des_cbc(
            b"short",
            b"12345678abcdefgh",
        )


def test_rsa_encrypt_decrypt_des_key():
    receiver_key = RSA.generate(2048)

    des_key, _ = generate_des_key_iv()

    encrypted = encrypt_des_key_rsa(
        des_key,
        receiver_key.publickey(),
    )

    decrypted = decrypt_des_key_rsa(
        encrypted,
        receiver_key,
    )

    assert encrypted != des_key
    assert decrypted == des_key


def test_full_sender_receiver_payload_success():
    receiver_key = RSA.generate(2048)

    plaintext = b"Lab 8: DES-CBC + SHA-256 + RSA-OAEP"

    packet, _des_key, _ciphertext, digest = build_sender_payload(
        plaintext,
        receiver_key.publickey(),
    )

    opened_plaintext, integrity_ok = open_receiver_payload(
        packet,
        receiver_key,
    )

    assert opened_plaintext == plaintext
    assert integrity_ok is True
    assert digest == sha256_digest(plaintext)


def test_tampered_hash_is_detected():
    receiver_key = RSA.generate(2048)

    packet, _des_key, _ciphertext, _digest = build_sender_payload(
        b"original",
        receiver_key.publickey(),
    )

    tampered_packet = packet[:-1] + bytes([packet[-1] ^ 0x01])

    plaintext, integrity_ok = open_receiver_payload(
        tampered_packet,
        receiver_key,
    )

    assert plaintext == b"original"
    assert integrity_ok is False


def test_tampered_ciphertext_fails_or_changes_integrity():
    receiver_key = RSA.generate(2048)

    packet, _des_key, _ciphertext, _digest = build_sender_payload(
        b"original message",
        receiver_key.publickey(),
    )

    mutable = bytearray(packet)

    mutable[-40] ^= 0x01

    try:
        plaintext, integrity_ok = open_receiver_payload(
            bytes(mutable),
            receiver_key,
        )

    except ValueError:
        return

    assert (
        plaintext != b"original message"
        or integrity_ok is False
    )
