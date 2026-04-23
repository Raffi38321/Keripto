import os
import argparse
from getpass import getpass

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SMG1"


# =====================
# KEY GENERATION
# =====================
def generate_keys(name):
    password = getpass(f"Masukkan password untuk {name} private key: ").encode()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # simpan private key (terenkripsi)
    with open(f"{name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        ))

    # simpan public key
    with open(f"{name}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Key untuk {name} berhasil dibuat")


# =====================
# ENCRYPT (Alice → Bob)
# =====================
def encrypt(sender, receiver, input_file, output_file):
    # baca file
    with open(input_file, "rb") as f:
        data = f.read()

    # load public key receiver (Bob)
    with open(f"{receiver}_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # generate AES key & nonce
    aes_key = os.urandom(32)   # AES-256
    nonce = os.urandom(12)     # GCM nonce

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    # encrypt AES key pakai RSA-OAEP
    c_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # simpan file terenkripsi
    with open(output_file, "wb") as f:
        f.write(MAGIC)
        f.write(len(c_key).to_bytes(2, "big"))
        f.write(c_key)
        f.write(nonce)
        f.write(ciphertext)

    print("Enkripsi berhasil")
    print(f"[INFO] Dari: {sender} → Ke: {receiver}")
    print(f"[INFO] Ukuran file: {len(data)} bytes")


# =====================
# DECRYPT (Bob)
# =====================
def decrypt(user, input_file, output_file):
    with open(input_file, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            print("Format file tidak valid (magic number salah)")
            return

        key_len = int.from_bytes(f.read(2), "big")
        c_key = f.read(key_len)
        nonce = f.read(12)
        ciphertext = f.read()

    if len(nonce) != 12:
        print("File rusak: nonce tidak valid")
        return

    password = getpass(f"Masukkan password private key {user}: ").encode()

    # load private key
    with open(f"{user}_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password
        )

    try:
        # decrypt AES key
        aes_key = private_key.decrypt(
            c_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # decrypt data
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        with open(output_file, "wb") as f:
            f.write(plaintext)

        print("Dekripsi berhasil")

    except Exception:
        print("Dekripsi gagal!")
        print("Kemungkinan penyebab:")
        print("- Kunci privat tidak cocok (bukan milik penerima)")
        print("- Password salah")
        print("- File telah dimodifikasi (auth tag tidak valid)")


# =====================
# CLI
# =====================
def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    # keygen
    k = subparsers.add_parser("keygen")
    k.add_argument("--name", required=True)

    # encrypt
    e = subparsers.add_parser("encrypt")
    e.add_argument("--from", required=True)
    e.add_argument("--to", required=True)
    e.add_argument("--in", required=True)
    e.add_argument("--out", required=True)

    # decrypt
    d = subparsers.add_parser("decrypt")
    d.add_argument("--as", required=True)
    d.add_argument("--in", required=True)
    d.add_argument("--out", required=True)

    args = parser.parse_args()

    if args.command == "keygen":
        generate_keys(args.name)

    elif args.command == "encrypt":
        encrypt(
            args.__dict__["from"],
            args.to,
            args.__dict__["in"],
            args.__dict__["out"]
        )

    elif args.command == "decrypt":
        decrypt(
            args.__dict__["as"],
            args.__dict__["in"],
            args.__dict__["out"]
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()