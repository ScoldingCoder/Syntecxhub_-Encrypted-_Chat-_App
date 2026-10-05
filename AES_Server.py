"""Multi-client encrypted chat server (hub model).

Each client gets its own ephemeral ECDH handshake and its own AES session key.
The server decrypts incoming messages, logs them, and re-encrypts them
separately for every other client.
"""
import logging
import socket
import threading

from Crypto.PublicKey import ECC

from chat_common import (CURVE, decrypt_message, encrypt_message, fingerprint,
                         handshake, recv_frame, send_frame)

HOST, PORT = "localhost", 5000
LOG_FILE = "chat_server.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"),
              logging.StreamHandler()],
)

clients = set()
clients_lock = threading.Lock()


class Client:
    def __init__(self, sock, addr, key):
        self.sock = sock
        self.addr = addr
        self.key = key
        self.name = f"{addr[0]}:{addr[1]}"
        self.send_lock = threading.Lock()  # stop two threads interleaving frames

    def send(self, text):
        blob = encrypt_message(self.key, text)  # new IV every call
        with self.send_lock:
            send_frame(self.sock, blob)


def broadcast(text, exclude=None):
    with clients_lock:
        targets = [c for c in clients if c is not exclude]
    for c in targets:
        try:
            c.send(text)
        except OSError as e:
            logging.warning("send to %s failed: %s", c.name, e)


def handle_client(sock, addr):
    client = None
    try:
        sock.settimeout(10)  # don't let a silent peer hold the handshake open
        session_key = handshake(sock, ECC.generate(curve=CURVE))  # ephemeral
        client = Client(sock, addr, session_key)
        logging.info("handshake done with %s, key fingerprint %s",
                     addr, fingerprint(session_key))

        name = decrypt_message(session_key, recv_frame(sock)).strip()
        sock.settimeout(None)
        if name:
            client.name = name[:32]
        with clients_lock:
            clients.add(client)
        logging.info("%s joined from %s", client.name, addr)
        client.send("Welcome, %s! Type /quit to leave." % client.name)
        broadcast(f"* {client.name} joined", exclude=client)

        while True:
            text = decrypt_message(session_key, recv_frame(sock))
            if text == "/quit":
                break
            logging.info("MSG %s: %s", client.name, text)
            broadcast(f"{client.name}: {text}", exclude=client)
    except (OSError, ValueError) as e:  # includes bad padding, bad key, drops
        logging.info("connection %s ended: %s", addr, e)
    except Exception:
        logging.exception("unexpected error with %s", addr)
    finally:
        if client is not None:
            with clients_lock:
                was_member = client in clients
                clients.discard(client)
            if was_member:
                logging.info("%s left", client.name)
                broadcast(f"* {client.name} left")
        sock.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    logging.info("listening on %s:%d (log: %s)", HOST, PORT, LOG_FILE)
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr),
                             daemon=True, name=f"client-{addr[1]}").start()
    except KeyboardInterrupt:
        logging.info("shutting down")
    finally:
        server.close()

if __name__ == "__main__":
    main()
