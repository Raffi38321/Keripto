import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Kriptografi modern via cryptography library
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("Library 'cryptography' belum terinstal.")
    print("Jalankan: pip install cryptography")
    sys.exit(1)


# ─────────────────────────────────────────────
# UTILITAS TAMPILAN
# ─────────────────────────────────────────────

WIDTH = 55

def garis(char="═"):
    return char * WIDTH

def header(judul):
    print(f"\n{garis()}")
    print(f"  {judul}")
    print(garis())

def footer():
    print(garis())

def baris(label, nilai):
    print(f"  {label:<12}: {nilai}")

def ok(pesan):
    print(f"  ✓  {pesan}")

def err(pesan):
    print(f"  ✗  {pesan}")

def info(pesan):
    print(f"  ℹ  {pesan}")


# ─────────────────────────────────────────────
# FUNGSI INTI KRIPTOGRAFI
# ─────────────────────────────────────────────

def hash_file(path: Path) -> bytes:
    """Hitung SHA-256 dari isi file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for blok in iter(lambda: f.read(65536), b""):
            sha256.update(blok)
    return sha256.digest()


def minta_password(konfirmasi=False) -> bytes:
    """Minta password dari pengguna (tersembunyi)."""
    pw = getpass.getpass("  🔑 Masukkan password untuk kunci privat: ")
    if not pw:
        print()
        err("Password tidak boleh kosong.")
        sys.exit(1)
    if konfirmasi:
        pw2 = getpass.getpass("  🔑 Konfirmasi password: ")
        if pw != pw2:
            print()
            err("Password tidak cocok.")
            sys.exit(1)
    print()
    return pw.encode()


def simpan_privat_key(privkey: Ed25519PrivateKey, path: Path, password: bytes):
    """Simpan private key ke PEM dengan enkripsi PBKDF2+AES."""
    pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    path.write_bytes(pem)


def muat_privat_key(path: Path, password: bytes) -> Ed25519PrivateKey:
    """Muat dan dekripsi private key dari file PEM."""
    try:
        pem = path.read_bytes()
        return serialization.load_pem_private_key(pem, password=password, backend=default_backend())
    except (ValueError, TypeError):
        err("Password salah atau file kunci rusak.")
        sys.exit(1)
    except FileNotFoundError:
        err(f"File kunci tidak ditemukan: {path}")
        sys.exit(1)


def simpan_publik_key(pubkey: Ed25519PublicKey, path: Path):
    """Simpan public key ke PEM (tidak terenkripsi)."""
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def muat_publik_key(path: Path) -> Ed25519PublicKey:
    """Muat public key dari file PEM."""
    try:
        pem = path.read_bytes()
        return serialization.load_pem_public_key(pem, backend=default_backend())
    except FileNotFoundError:
        err(f"File kunci publik tidak ditemukan: {path}")
        sys.exit(1)
    except (ValueError, TypeError) as e:
        err(f"File kunci publik tidak valid: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────
# PERINTAH: KEYGEN
# ─────────────────────────────────────────────

def cmd_keygen(args):
    nama = args.name
    priv_path = Path(f"{nama}.priv")
    pub_path  = Path(f"{nama}.pub")

    header(f"Generate Pasangan Kunci Ed25519 — {nama}")

    if priv_path.exists() or pub_path.exists():
        info(f"File {priv_path} atau {pub_path} sudah ada.")
        jawab = input("  Timpa file yang ada? [y/N]: ").strip().lower()
        if jawab != "y":
            info("Dibatalkan.")
            footer()
            return

    password = minta_password(konfirmasi=True)

    # Generate pasangan kunci
    privkey = Ed25519PrivateKey.generate()
    pubkey  = privkey.public_key()

    simpan_privat_key(privkey, priv_path, password)
    simpan_publik_key(pubkey, pub_path)

    # Tampilkan fingerprint publik key
    pub_bytes = pubkey.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    fingerprint = hashlib.sha256(pub_bytes).hexdigest()[:16]

    ok(f"Kunci privat tersimpan : {priv_path}  (dilindungi password)")
    ok(f"Kunci publik tersimpan  : {pub_path}")
    baris("Algoritma", "Ed25519")
    baris("Enkripsi", "PBKDF2 + AES-256-CBC")
    baris("Fingerprint", fingerprint + "...")
    footer()


# ─────────────────────────────────────────────
# PERINTAH: SIGN
# ─────────────────────────────────────────────

def cmd_sign(args):
    key_path  = Path(args.key)
    file_path = Path(args.file)
    sig_path  = Path(args.sig) if args.sig else Path(args.file + ".sig")

    header("Menandatangani Dokumen")

    if not file_path.exists():
        err(f"File tidak ditemukan: {file_path}")
        footer()
        sys.exit(1)

    password = minta_password()
    privkey  = muat_privat_key(key_path, password)

    # Hash file
    digest = hash_file(file_path)

    # Tanda tangani digest (Ed25519 menandatangani data mentah)
    signature = privkey.sign(digest)

    # Simpan signature + metadata ke file .sig (JSON)
    sig_data = {
        "algoritma": "Ed25519",
        "hash_algo": "SHA-256",
        "hash": digest.hex(),
        "signature": base64.b64encode(signature).decode(),
        "file": str(file_path),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "kunci": key_path.stem,
    }
    sig_path.write_text(json.dumps(sig_data, indent=2, ensure_ascii=False))

    ok(f"File ditandatangani       : {file_path}")
    ok(f"Signature disimpan ke     : {sig_path}")
    baris("Hash SHA-256", digest.hex()[:32] + "...")
    baris("Timestamp", sig_data["timestamp"])
    footer()


# ─────────────────────────────────────────────
# PERINTAH: VERIFY
# ─────────────────────────────────────────────

def cmd_verify(args):
    key_path  = Path(args.key)
    file_path = Path(args.file)
    sig_path  = Path(args.sig) if args.sig else Path(args.file + ".sig")

    header("Hasil Verifikasi Tanda Tangan Digital")

    # Validasi keberadaan file
    for p in [file_path, sig_path, key_path]:
        if not p.exists():
            err(f"File tidak ditemukan: {p}")
            footer()
            sys.exit(1)

    # Muat data signature
    try:
        sig_data = json.loads(sig_path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        err("File .sig tidak valid atau rusak.")
        footer()
        sys.exit(1)

    pubkey    = muat_publik_key(key_path)
    digest    = hash_file(file_path)
    hash_hex  = digest.hex()

    baris("File", str(file_path))
    baris("Algoritma", sig_data.get("algoritma", "Ed25519"))
    baris("Hash", hash_hex[:32] + "...")
    baris("Timestamp", sig_data.get("timestamp", "-"))
    print()

    # Cek konsistensi hash
    hash_tersimpan = sig_data.get("hash", "")
    if hash_tersimpan != hash_hex:
        baris("Status", "✗ TIDAK VALID")
        baris("Pesan", "File telah dimodifikasi sejak ditandatangani!")
        footer()
        sys.exit(2)

    # Verifikasi signature kriptografis
    try:
        sig_bytes = base64.b64decode(sig_data["signature"])
        pubkey.verify(sig_bytes, digest)
        baris("Status", "✓ VALID")
        baris("Pesan", "Dokumen asli. Tanda tangan sah.")
    except InvalidSignature:
        baris("Status", "✗ TIDAK VALID")
        baris("Pesan", "Tanda tangan tidak cocok! File atau sig mungkin dimanipulasi.")
        footer()
        sys.exit(2)
    except Exception as e:
        baris("Status", "✗ ERROR")
        baris("Pesan", str(e))
        footer()
        sys.exit(2)

    footer()


# ─────────────────────────────────────────────
# PERINTAH: MANIFEST
# ─────────────────────────────────────────────

def cmd_manifest(args):
    key_path    = Path(args.key)
    folder_path = Path(args.folder)
    out_path    = folder_path / "manifest.json"

    header(f"Membuat Manifest Folder — {folder_path}")

    if not folder_path.is_dir():
        err(f"Folder tidak ditemukan: {folder_path}")
        footer()
        sys.exit(1)

    password = minta_password()
    privkey  = muat_privat_key(key_path, password)

    # Kumpulkan semua file (kecuali manifest itu sendiri dan .sig)
    files = sorted([
        f for f in folder_path.rglob("*")
        if f.is_file()
        and f.name != "manifest.json"
        and not f.suffix == ".sig"
    ])

    if not files:
        err("Tidak ada file di folder ini.")
        footer()
        sys.exit(1)

    entri = []
    for f in files:
        digest    = hash_file(f)
        signature = privkey.sign(digest)
        entri.append({
            "file": str(f.relative_to(folder_path)),
            "hash_algo": "SHA-256",
            "hash": digest.hex(),
            "signature": base64.b64encode(signature).decode(),
            "algoritma": "Ed25519",
        })
        ok(f"Ditandatangani: {f.relative_to(folder_path)}")

    manifest = {
        "dibuat": datetime.utcnow().isoformat() + "Z",
        "kunci": key_path.stem,
        "total_file": len(entri),
        "file": entri,
    }
    out_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

    print()
    ok(f"Manifest tersimpan: {out_path}")
    baris("Total file", str(len(entri)))
    footer()


# ─────────────────────────────────────────────
# PERINTAH: VERIFY-MANIFEST
# ─────────────────────────────────────────────

def cmd_verify_manifest(args):
    key_path     = Path(args.key)
    manifest_path = Path(args.manifest)

    header("Verifikasi Manifest")

    if not manifest_path.exists():
        err(f"File manifest tidak ditemukan: {manifest_path}")
        footer()
        sys.exit(1)

    folder = manifest_path.parent
    pubkey = muat_publik_key(key_path)

    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError:
        err("File manifest tidak valid.")
        footer()
        sys.exit(1)

    baris("Dibuat", manifest.get("dibuat", "-"))
    baris("Kunci", manifest.get("kunci", "-"))
    baris("Total", str(manifest.get("total_file", "?")) + " file")
    print()

    semua_valid = True
    for entri in manifest.get("file", []):
        file_path = folder / entri["file"]
        label     = entri["file"]

        if not file_path.exists():
            err(f"[HILANG]  {label}")
            semua_valid = False
            continue

        digest = hash_file(file_path)
        if digest.hex() != entri.get("hash", ""):
            err(f"[DIUBAH]  {label}")
            semua_valid = False
            continue

        try:
            sig_bytes = base64.b64decode(entri["signature"])
            pubkey.verify(sig_bytes, digest)
            ok(f"[VALID]   {label}")
        except InvalidSignature:
            err(f"[SIG SALAH] {label}")
            semua_valid = False

    print()
    if semua_valid:
        ok("Semua file dalam manifest VALID dan tidak dimodifikasi.")
    else:
        err("Beberapa file TIDAK VALID atau hilang. Periksa output di atas.")

    footer()
    sys.exit(0 if semua_valid else 2)


# ─────────────────────────────────────────────
# ARGPARSE & ENTRY POINT
# ─────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="docsign",
        description="Alat Tanda Tangan Digital Ed25519 — Aman & Mudah Digunakan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python docsign.py keygen --name alice
  python docsign.py sign   --key alice.priv --file kontrak.pdf
  python docsign.py verify --key alice.pub  --file kontrak.pdf
  python docsign.py manifest --key alice.priv --folder ./dokumen/
  python docsign.py verify-manifest --key alice.pub --manifest ./dokumen/manifest.json
        """,
    )
    sub = parser.add_subparsers(dest="perintah", required=True)

    # keygen
    p_kg = sub.add_parser("keygen", help="Generate pasangan kunci Ed25519")
    p_kg.add_argument("--name", required=True, metavar="NAMA",
                      help="Nama pengguna (menghasilkan NAMA.priv dan NAMA.pub)")

    # sign
    p_sg = sub.add_parser("sign", help="Tandatangani sebuah file")
    p_sg.add_argument("--key",  required=True, metavar="FILE.priv")
    p_sg.add_argument("--file", required=True, metavar="FILE")
    p_sg.add_argument("--sig",  metavar="FILE.sig",
                      help="Path output .sig (default: FILE.sig)")

    # verify
    p_vr = sub.add_parser("verify", help="Verifikasi tanda tangan sebuah file")
    p_vr.add_argument("--key",  required=True, metavar="FILE.pub")
    p_vr.add_argument("--file", required=True, metavar="FILE")
    p_vr.add_argument("--sig",  metavar="FILE.sig",
                      help="Path file .sig (default: FILE.sig)")

    # manifest
    p_mf = sub.add_parser("manifest", help="Tandatangani semua file dalam folder")
    p_mf.add_argument("--key",    required=True, metavar="FILE.priv")
    p_mf.add_argument("--folder", required=True, metavar="FOLDER")

    # verify-manifest
    p_vm = sub.add_parser("verify-manifest", help="Verifikasi manifest folder")
    p_vm.add_argument("--key",      required=True, metavar="FILE.pub")
    p_vm.add_argument("--manifest", required=True, metavar="manifest.json")

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    dispatch = {
        "keygen":          cmd_keygen,
        "sign":            cmd_sign,
        "verify":          cmd_verify,
        "manifest":        cmd_manifest,
        "verify-manifest": cmd_verify_manifest,
    }
    dispatch[args.perintah](args)


if __name__ == "__main__":
    main()
