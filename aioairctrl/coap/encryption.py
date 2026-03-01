"""Encryption used by the Philips air purifier CoAP protocol.

Wire format for an encrypted payload (all hex-encoded, uppercase ASCII):

    [client_key: 8 chars][ciphertext: variable][sha256_digest: 64 chars]

The client_key embedded in the payload is a 4-byte big-endian counter
(incremented before each encrypt call) expressed as 8 hex characters.

Key derivation: MD5("JiangPan" + client_key), split into two equal halves.
The first half becomes the AES-128 key, the second half the CBC IV.
"""
import hashlib

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


class DigestMismatchException(Exception):
    pass


class EncryptionContext:
    # Protocol-defined secret mixed into every key derivation.
    SECRET_KEY = "JiangPan"

    def __init__(self):
        # Hex-encoded 4-byte counter, e.g. "00A3F1C2". None until set_client_key is called.
        self._client_key = None

    def set_client_key(self, client_key):
        self._client_key = client_key

    def _increment_client_key(self):
        if self._client_key is None:
            raise ValueError("Client key must be set before incrementing")
        # Wrap around at 0xFFFFFFFF so the counter stays within 4 bytes.
        client_key_next = ((int(self._client_key, 16) + 1) % 0x100000000).to_bytes(4, byteorder="big").hex().upper()
        self._client_key = client_key_next

    def _create_cipher(self, key: str):
        # Derive a 32-char hex digest, then split it: first half → AES key, second half → IV.
        key_and_iv = hashlib.md5((self.SECRET_KEY + key).encode()).hexdigest().upper()
        half_keylen = len(key_and_iv) // 2
        secret_key = key_and_iv[0:half_keylen]
        iv = key_and_iv[half_keylen:]
        cipher = AES.new(
            key=secret_key.encode(),
            mode=AES.MODE_CBC,
            iv=iv.encode(),
        )
        return cipher

    def encrypt(self, payload: str) -> str:
        # Increment first so the key embedded in the output is always ahead of
        # the last key seen by the device, preventing replay of old counters.
        self._increment_client_key()
        key = self._client_key
        plaintext_padded = pad(payload.encode(), 16, style="pkcs7")
        cipher = self._create_cipher(key)
        ciphertext = cipher.encrypt(plaintext_padded).hex().upper()
        # Integrity check: SHA-256 over (key + ciphertext) appended at the end.
        digest = hashlib.sha256((key + ciphertext).encode()).hexdigest().upper()
        return key + ciphertext + digest

    def decrypt(self, payload_encrypted: str) -> str:
        # Parse the fixed-width envelope: 8-char key, 64-char digest at the tail.
        key = payload_encrypted[0:8]
        ciphertext = payload_encrypted[8:-64]
        digest = payload_encrypted[-64:]
        digest_calculated = hashlib.sha256((key + ciphertext).encode()).hexdigest().upper()
        if digest != digest_calculated:
            raise DigestMismatchException
        cipher = self._create_cipher(key)
        plaintext_padded = cipher.decrypt(bytes.fromhex(ciphertext))
        plaintext_unpadded = unpad(plaintext_padded, 16, style="pkcs7")
        return plaintext_unpadded.decode()
