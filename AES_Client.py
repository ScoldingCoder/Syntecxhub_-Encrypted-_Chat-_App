"""Encrypted chat client: ECDH handshake, then encrypted send/receive."""
import socket
import threading

from Crypto.PublicKey import ECC

from chat_common import (CURVE, decrypt_message, encrypt_message, fingerprint,
                         handshake, recv_frame, send_frame)

HOST, PORT = "localhost", 5000


def receive_loop(sock, key, stop):
    try:
        while not stop.is_set():
            print("\r" + decrypt_message(key, recv_frame(sock)))
    except (OSError, ValueError):
        pass
    finally:
        if not stop.is_set():
            print("\n[disconnected - press Enter to exit]")
        stop.set()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    key = handshake(sock, ECC.generate(curve=CURVE))
    print(f"Secure channel established. Key fingerprint: {fingerprint(key)}")

    name = input("Your name: ").strip()
    send_frame(sock, encrypt_message(key, name))

    stop = threading.Event()
    threading.Thread(target=receive_loop, args=(sock, key, stop),
                     daemon=True).start()

    try:
        while not stop.is_set():
            text = input()
            if stop.is_set():
                break
            if not text:
                continue
            send_frame(sock, encrypt_message(key, text))
            if text == "/quit":
                break
    except (EOFError, KeyboardInterrupt, OSError):
        pass
    finally:
        stop.set()
        sock.close()


if __name__ == "__main__":
    main()