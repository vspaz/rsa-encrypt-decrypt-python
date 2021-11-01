# cryptolib
a small library to easily encrypt/decrypt with RSA public/private key pair.

## how to:

### Generate the key pair:

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -out public.pem -pubout -outform PEM
```

### Install cryptolib

```bash
git clone https://github.com/vspaz/rsa-encrypt-decrypt-golang.git
cd rsa-encrypt-decrypt-golang

python3 setup.py install
```
