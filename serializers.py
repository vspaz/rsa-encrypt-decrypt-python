import base64
import logging
import os
import traceback

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

import ujson

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %X",
)


def to_json(serializable):
    return ujson.dumps(serializable)


def from_json(deserializable):
    return ujson.loads(deserializable)


def from_file(file_path, mode='rb'):
    try:
        with open(file=file_path, mode=mode) as fh:
            return fh.read()
    except FileNotFoundError:
        logging.error('failed to load private key from %s', file_path)
        raise FileNotFoundError from None
    except PermissionError:
        logging.error('failed to read %s; wrong permissions', file_path)
        raise PermissionError from None


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
    except Exception:
        logging.error('error decrypting text: %s', traceback.format_exc())
    raise RuntimeError from None


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
    except Exception:
        logging.error('error encrypting text: %s', traceback.format_exc())
    raise RuntimeError from None


if __name__ == "__main__":
    text = "some text"
    logging.info("original text: %s", text)
    public_key = open(
        os.path.join(
            os.getcwd(),
            "tests/data/public.pem",
        ),
        "rb",
    ).read()
    imported_public_key = load_key(file_contents=public_key)
    public_key_cipher = create_cipher(imported_public_key)
    encrypted_message = encrypt_text(
        unencrypted_text=text,
        cipher=public_key_cipher,
    )
    logging.info("RSA-encrypted and base85-encoded text: %s", encrypted_message)

    pivate_key = open(
        os.path.join(
            os.getcwd(),
            "tests/data/private.pem"
        ), "rb",
    ).read()
    imported_private_key = load_key(file_contents=pivate_key)
    private_key_cipher = create_cipher(imported_private_key)
    decoded_text = decrypt_text(encrypted_message, cipher=private_key_cipher)
    logging.info("decoded text: %s", decoded_text)
