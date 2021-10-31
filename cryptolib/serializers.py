import base64
import logging

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def to_bytes(serializable, encoding='UTF-8'):
    return serializable.encode(encoding=encoding)


def from_bytes(deserializable, encoding='UTF-8'):
    return deserializable.decode(encoding=encoding)


def to_base_85(serializable):
    return base64.a85encode(serializable)


def from_base_85(deserializable):
    return base64.a85decode(deserializable)


def load_key(file_contents):
    return RSA.importKey(file_contents)


def create_cipher(key):
    return PKCS1_OAEP.new(key)


def decrypt_text(encrypted_text, cipher):
    try:
        return from_bytes(
            deserializable=cipher.decrypt(
                from_base_85(
                    deserializable=to_bytes(
                        serializable=encrypted_text,
                    ),
                ),
            ),
        )
    except Exception as exc:
        logging.error(f'error decrypting text: {exc!r}')
        raise RuntimeError from exc


def encrypt_text(unencrypted_text, cipher):
    try:
        return from_bytes(
            deserializable=to_base_85(
                serializable=cipher.encrypt(
                    to_bytes(
                        serializable=unencrypted_text,
                    ),
                ),
            ),
        )
    except Exception as exc:
        logging.error(f'error encrypting text: {exc!r}')
        raise RuntimeError from exc


class Encoder:
    def __init__(self, private_key: str = None, public_key: str = None):
        if private_key:
            self._private_key = self.load_key(key=private_key.encode())
        if public_key:
            self._public_key = self.load_key(key=public_key.encode())

    @staticmethod
    def to_bytes(serializable, encoding='UTF-8'):
        return serializable.encode(encoding=encoding)

    @staticmethod
    def from_bytes(deserializable, encoding='UTF-8'):
        return deserializable.decode(encoding=encoding)

    @staticmethod
    def to_base_85(serializable):
        return base64.a85encode(serializable)

    @staticmethod
    def from_base_85(deserializable):
        return base64.a85decode(deserializable)

    @staticmethod
    def load_key(key):
        return RSA.importKey(key)

    @staticmethod
    def _create_cipher(key):
        return PKCS1_OAEP.new(key)

    def encrypt_with_public_key(self, unencrypted_text):
        cipher = self._create_cipher(key=self._public_key)
        return cipher.encrypt(message=to_bytes(serializable=unencrypted_text))

    def decrypt_with_private_key(self, encrypted_text):
        cipher = self._create_cipher(key=self._private_key)
        return cipher.decrypt(ct=encrypted_text)
