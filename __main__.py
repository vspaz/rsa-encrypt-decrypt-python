import logging
import os

from cryptolib import serializers as ser


def main():
    text = "some text"
    logging.info("original text: %s", text)
    public_key = open(
        os.path.join(
            os.getcwd(),
            "tests/data/public.pem",
        ),
        "rb",
    ).read()
    imported_public_key = ser.load_key(file_contents=public_key)
    public_key_cipher = ser.create_cipher(key=imported_public_key)
    encrypted_message = ser.encrypt_text(
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
    imported_private_key = ser.load_key(file_contents=pivate_key)
    private_key_cipher = ser.create_cipher(key=imported_private_key)
    decoded_text = ser.decrypt_text(
        encrypted_text=encrypted_message,
        cipher=private_key_cipher,
    )
    logging.info("decoded text: %s", decoded_text)


if __name__ == "__main__":
    main()
