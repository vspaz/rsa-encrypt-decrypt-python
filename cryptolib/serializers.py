import base64
from typing import Union

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class CryptoBase:
    @staticmethod
    def load_key(key):
        return RSA.importKey(key)

    @staticmethod
    def _create_cipher(key):
        return PKCS1_OAEP.new(key)

    @staticmethod
    def to_bytes(serializable: str, encoding="UTF-8") -> bytes:
        return serializable.encode(encoding=encoding)

    @staticmethod
    def from_bytes(deserializable: bytes, encoding="UTF-8") -> str:
        return deserializable.decode(encoding=encoding)


class Encoder(CryptoBase):
    def __init__(self, public_key: str):
        self._public_key = self.load_key(key=public_key.encode())

    def encrypt(self, unencrypted_text: str) -> bytes:
        cipher = self._create_cipher(key=self._public_key)
        return cipher.encrypt(message=unencrypted_text.encode())

    @staticmethod
    def to_base_85(serializable: Union[str, bytes]) -> bytes:
        return base64.a85encode(serializable)

    @staticmethod
    def to_base_64(serializable: Union[str, bytes]) -> bytes:
        return base64.b64encode(serializable)


class Decoder(CryptoBase):
    def __init__(self, private_key: str):
        self._private_key = self.load_key(key=private_key.encode())

    def decrypt(self, encrypted_text: bytes) -> bytes:
        cipher = self._create_cipher(key=self._private_key)
        return cipher.decrypt(ciphertext=encrypted_text)

    @staticmethod
    def from_base_85(deserializable: Union[str, bytes]) -> bytes:
        return base64.a85decode(deserializable)

    @staticmethod
    def from_base_64(deserializable: Union[str, bytes]) -> bytes:
        return base64.b64decode(deserializable)
