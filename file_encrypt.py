import os
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

SALT_SIZE = 16
NONCE_SIZE = 12
ITERATIONS = 100000
KEY_SIZE = 32 

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Enkrip
def encrypt_file(input_file, output_file, password):
    try:
        with open(input_file, "rb") as f:
            data = f.read()

        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        aad = os.path.basename(input_file).encode()

        ciphertext = aesgcm.encrypt(nonce, data, aad)

        tag_length = 16  
        filename = os.path.basename(input_file).encode()
        filename_len = len(filename)

        with open(output_file, "wb") as f:
            f.write(salt)
            f.write(nonce)
            f.write(tag_length.to_bytes(4, "big"))
            f.write(filename_len.to_bytes(2, "big")) 
            f.write(filename)                         
            f.write(ciphertext)

        print("Enkripsi berhasil")

    except FileNotFoundError:
        print("File gak ada blog")
    except Exception as e:
        print(f"bagnsat  di enkrip: {e}")

# DEkrip
def decrypt_file(input_file, output_file, password):
    try:
        with open(input_file, "rb") as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(NONCE_SIZE)
            tag_length = int.from_bytes(f.read(4), "big")

            filename_len = int.from_bytes(f.read(2), "big")
            filename = f.read(filename_len)

            ciphertext = f.read()

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        aad = filename  

        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        with open(output_file, "wb") as f:
            f.write(plaintext)

        print("Dekripsi berhasil")

    except FileNotFoundError:
        print("File gak ada blog")
    except Exception as e:
        if "InvalidTag" in str(e):
            print("Password salah atau file telah dimodifikasi!")
        else:
            print(f" Error bangsat: {e}")

# ======================
# CLI
# ======================
def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM File Encryptor")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    parser.add_argument("--password", required=True)

    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.input_file, args.output_file, args.password)
    else:
        decrypt_file(args.input_file, args.output_file, args.password)

if __name__ == "__main__":
    main()