import socket
import threading

import pytest

from secure_transfer_utils import (
    build_secure_packet,
    recv_exact,
    recv_secure_packet,
)


def test_recv_secure_packet_over_local_socket():

    packet = build_secure_packet(
        b"k" * 256,
        b"c" * 24,
        b"h" * 32,
    )

    left, right = socket.socketpair()

    def sender():
        with left:
            left.sendall(packet)

    thread = threading.Thread(target=sender)

    thread.start()

    with right:
        received = recv_secure_packet(right)

    thread.join(timeout=2)

    assert received == packet


def test_recv_exact_reads_correct_bytes():

    left, right = socket.socketpair()

    def sender():
        with left:
            left.sendall(b"abcdefgh")

    thread = threading.Thread(target=sender)

    thread.start()

    with right:
        data = recv_exact(right, 8)

    thread.join(timeout=2)

    assert data == b"abcdefgh"


def test_recv_exact_rejects_invalid_size():

    left, right = socket.socketpair()

    with left, right:

        with pytest.raises(ValueError):

            recv_exact(right, 0)


def test_recv_secure_packet_handles_small_chunks():

    packet = build_secure_packet(
        b"k" * 256,
        b"c" * 24,
        b"h" * 32,
    )

    left, right = socket.socketpair()

    def sender():

        with left:

            for i in range(0, len(packet), 10):
                left.sendall(packet[i:i + 10])

    thread = threading.Thread(target=sender)

    thread.start()

    with right:

        received = recv_secure_packet(right)

    thread.join(timeout=2)

    assert received == packet
