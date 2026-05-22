import pytest

from secure_transfer_utils import (
    SHA256_DIGEST_SIZE,
    build_secure_packet,
    parse_secure_packet,
    sha256_digest,
)


def test_sha256_digest_has_32_bytes():

    digest = sha256_digest(b"FIT4012 Lab 8")

    assert isinstance(digest, bytes)
    assert len(digest) == SHA256_DIGEST_SIZE


def test_lab8_packet_format_order():

    encrypted_key = b"k" * 256
    ciphertext = b"c" * 24
    digest = b"h" * 32

    packet = build_secure_packet(
        encrypted_key,
        ciphertext,
        digest,
    )

    assert packet[:4] == (256).to_bytes(4, "big")

    assert packet[4:260] == encrypted_key

    assert packet[260:264] == (24).to_bytes(4, "big")

    assert packet[264:288] == ciphertext

    assert packet[288:] == digest

    parsed_key, parsed_ciphertext, parsed_digest = (
        parse_secure_packet(packet)
    )

    assert parsed_key == encrypted_key

    assert parsed_ciphertext == ciphertext

    assert parsed_digest == digest


def test_packet_rejects_wrong_hash_size():

    with pytest.raises(ValueError):

        build_secure_packet(
            b"k" * 256,
            b"c" * 16,
            b"short",
        )


def test_packet_rejects_extra_bytes():

    packet = (
        build_secure_packet(
            b"k" * 256,
            b"c" * 16,
            b"h" * 32,
        )
        + b"extra"
    )

    with pytest.raises(ValueError):

        parse_secure_packet(packet)


def test_packet_parse_roundtrip():

    encrypted_key = b"A" * 256
    ciphertext = b"B" * 64
    digest = sha256_digest(b"hello")

    packet = build_secure_packet(
        encrypted_key,
        ciphertext,
        digest,
    )

    key, cipher, parsed_digest = parse_secure_packet(packet)

    assert key == encrypted_key
    assert cipher == ciphertext
    assert parsed_digest == digest


def test_packet_rejects_invalid_header():

    with pytest.raises(ValueError):

        parse_secure_packet(b"123")
