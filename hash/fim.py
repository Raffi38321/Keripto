import os
import json
import hashlib
import hmac
import argparse

BASELINE_FILE = "baseline.json"


# =========================
# HASH FILE SHA-256
# =========================
def sha256_file(filepath):
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


# =========================
# SCAN FOLDER
# =========================
def scan_folder(folder):
    data = {}

    for root, dirs, files in os.walk(folder):
        for file in files:
            full_path = os.path.join(root, file)

            # jangan scan baseline sendiri
            if file == BASELINE_FILE:
                continue

            try:
                file_hash = sha256_file(full_path)
                relative_path = os.path.relpath(full_path, folder)
                data[relative_path] = file_hash

            except Exception as e:
                print(f"[ERROR] Gagal membaca {full_path}: {e}")

    return data


# =========================
# HMAC
# =========================
def generate_hmac(data, password):
    json_data = json.dumps(data, sort_keys=True).encode()

    return hmac.new(
        password.encode(),
        json_data,
        hashlib.sha256
    ).hexdigest()


# =========================
# INIT BASELINE
# =========================
def init_baseline(folder, password):
    files_data = scan_folder(folder)

    print(f"[INIT] Memindai {len(files_data)} file...")

    baseline = {
        "files": files_data,
        "hmac": generate_hmac(files_data, password)
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    print(f"[INIT] Baseline disimpan: {BASELINE_FILE} (HMAC dilindungi)")


# =========================
# CHECK INTEGRITY
# =========================
def check_integrity(folder, password):

    if not os.path.exists(BASELINE_FILE):
        print("[ERROR] baseline.json tidak ditemukan!")
        return

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    baseline_files = baseline["files"]
    baseline_hmac = baseline["hmac"]

    # verifikasi HMAC
    current_hmac = generate_hmac(baseline_files, password)

    if not hmac.compare_digest(current_hmac, baseline_hmac):
        print("[ERROR] Baseline dimodifikasi! HMAC tidak valid.")
        return

    current_files = scan_folder(folder)

    print(f"[CHECK] Memindai {len(current_files)} file...")

    unchanged = 0

    # cek file baru & berubah
    for path, current_hash in current_files.items():

        if path not in baseline_files:
            print(f"[BARU] {path}")

        else:
            baseline_hash = baseline_files[path]

            if current_hash == baseline_hash:
                unchanged += 1
            else:
                print(f"[UBAH] {path}")
                print(f"Baseline: {baseline_hash}")
                print(f"Sekarang : {current_hash}")

    # cek file hilang
    for path in baseline_files:
        if path not in current_files:
            print(f"[HAPUS] {path}")

    print(f"[OK] {unchanged} file tidak berubah")


# =========================
# CLI
# =========================
def main():

    parser = argparse.ArgumentParser(description="File Integrity Monitor")

    parser.add_argument(
        "command",
        choices=["init", "check"]
    )

    parser.add_argument("folder")

    parser.add_argument(
        "--password",
        required=True
    )

    args = parser.parse_args()

    if args.command == "init":
        init_baseline(args.folder, args.password)

    elif args.command == "check":
        check_integrity(args.folder, args.password)


if __name__ == "__main__":
    main()
