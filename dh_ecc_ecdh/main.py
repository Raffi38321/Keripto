from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import binascii

# =========================
# Helper Functions
# =========================
def to_hex(b):
    return binascii.hexlify(b).decode()

def derive_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 = 32 bytes
        salt=None,
        info=b'handshake data'
    )
    return hkdf.derive(shared_secret)

# =========================
# 1. Generate Key Pair
# =========================
alice_private = x25519.X25519PrivateKey.generate()
bob_private = x25519.X25519PrivateKey.generate()

alice_public = alice_private.public_key()
bob_public = bob_private.public_key()

print("[Alice] Public Key:", to_hex(alice_public.public_bytes_raw()))
print("[Bob]   Public Key:", to_hex(bob_public.public_bytes_raw()))

# =========================
# 2. Key Exchange (ECDH)
# =========================
alice_shared = alice_private.exchange(bob_public)
bob_shared = bob_private.exchange(alice_public)

print("\n[Shared Secret]")
print("Alice:", to_hex(alice_shared))
print("Bob  :", to_hex(bob_shared))

# =========================
# 3. Key Derivation (HKDF)
# =========================
alice_session_key = derive_key(alice_shared)
bob_session_key = derive_key(bob_shared)

print("\n[Session Key]")
print("Alice:", to_hex(alice_session_key))
print("Bob  :", to_hex(bob_session_key))

# =========================
# 4. Encryption (Alice → Bob)
# =========================
message = b"Halo Bob, ini pesan rahasia!"
print("\n[Alice] Pesan asli:", message.decode())

aesgcm = AESGCM(alice_session_key)
nonce = os.urandom(12)

ciphertext = aesgcm.encrypt(nonce, message, None)

print("[Alice] Ciphertext:")
print("nonce =", to_hex(nonce))
print("ct    =", to_hex(ciphertext))

# =========================
# 5. Decryption (Bob)
# =========================
aesgcm_bob = AESGCM(bob_session_key)

decrypted = aesgcm_bob.decrypt(nonce, ciphertext, None)

print("\n[Bob] Terdekripsi:", decrypted.decode(), "✓")

# =========================
# 6. Simulasi Session Baru (Isolasi)
# =========================
print("\n=== Simulasi Session Baru ===")

# Generate key baru (misal Alice ganti key)
alice_private_new = x25519.X25519PrivateKey.generate()
alice_public_new = alice_private_new.public_key()

# Exchange lagi
alice_shared_new = alice_private_new.exchange(bob_public)

# Derive key baru
alice_session_new = derive_key(alice_shared_new)

print("[Session baru] Key:", to_hex(alice_session_new))

# Coba decrypt pesan lama pakai key baru (HARUS GAGAL
try:
    aesgcm_new = AESGCM(alice_session_new)
    aesgcm_new.decrypt(nonce, ciphertext, None)
    print("❌ ERROR: Harusnya tidak bisa decrypt!")
except Exception as e:
    print("✓ Tidak bisa decrypt pesan lama (aman)")
