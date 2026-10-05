"""Shared helpers: message framing, ECDH handshake, AES-CBC encrypt/decrypt."""
import struct

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHAKE128
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

CURVE = "p256"
MAX_FRAME = 64 * 1024  # refuse absurdly large frames


# ---------- framing: 4-byte big-endian length prefix + payload ----------
def recv_exact(sock, n):
    """Keep calling recv() until exactly n bytes have arrived."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_frame(sock):
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    if length > MAX_FRAME:
        raise ValueError(f"frame too large: {length} bytes")
    return recv_exact(sock, length)


# ---------- key exchange ----------
def kdf(shared_secret):
    # Must be identical on both sides.
    return SHAKE128.new(shared_secret).read(32)


def handshake(sock, my_key):
    """Send our public key, read the peer's, return the 32-byte AES session key.

    Both sides send first and then read; the frames are tiny, so this cannot
    deadlock on socket buffers.
    """
    send_frame(sock, my_key.public_key().export_key(format="DER"))
    peer_public = ECC.import_key(recv_frame(sock))  # ValueError on garbage
    return key_agreement(static_priv=my_key, static_pub=peer_public, kdf=kdf)


def fingerprint(session_key):
    """Short value both users can compare out-of-band to spot a MITM."""
    return SHA256.new(b"fingerprint" + session_key).hexdigest()[:16]


# ---------- message encryption: IV (16 bytes) || AES-CBC ciphertext ----------
def encrypt_message(key, text):
    iv = get_random_bytes(16)  # fresh IV for every message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))


def decrypt_message(key, blob):
    if len(blob) < 32 or len(blob) % 16 != 0:
        raise ValueError("malformed ciphertext")
    iv, ciphertext = blob[:16], blob[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8")
