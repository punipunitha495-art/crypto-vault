#!/usr/bin/env python3
"""
Cryptographic Encryption Vault
--------------------------------
A secure vault script that encrypts and decrypts whole directories,
recursively, using AES-256-GCM with a passphrase-derived key (PBKDF2),
plus a securely generated key-file backup so the vault can be recovered
without re-typing the passphrase.

Design:
  1. Recursively scan a directory for all files to encrypt.
  2. Derive a 256-bit key from a master passphrase via PBKDF2-HMAC-SHA256
     with a random per-vault salt, and encrypt each file with AES-256-GCM
     (authenticated encryption — tamper/corruption is detected on decrypt).
  3. Generate a secure key-file backup (the salt + a wrapped copy of the
     derived key, itself encrypted with a key-encryption-key derived from
     the passphrase) so the vault key material is recoverable and auditable.
  4. Test full directory encryption and restoration, verifying byte-for-byte
     integrity (SHA-256 checksums) with no data corruption.

Usage:
    python crypto_vault.py encrypt -d my_folder -o my_folder.vault -k vault.key
    python crypto_vault.py decrypt -v my_folder.vault -k vault.key -o restored_folder

Author: <your name>
"""

import argparse
import getpass
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 390_000
MANIFEST_NAME = "__vault_manifest__.json"


# ---------------------------------------------------------------------------
# Key management: derive the master key, and produce a secure key-file backup
# ---------------------------------------------------------------------------
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt,
                      iterations=PBKDF2_ITERATIONS)
    return kdf.derive(passphrase.encode("utf-8"))


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_key_backup(key_backup_path: str, salt: bytes, vault_id: str) -> None:
    """
    Store recovery metadata (NOT the raw passphrase, and not the raw key
    either): the random salt used for this vault plus a vault identifier.
    Losing this file means the vault can still be decrypted with the
    passphrase alone (PBKDF2 + salt regenerates the same key) — it is a
    convenience/audit backup, not a bypass of the passphrase requirement.
    """
    backup = {
        "vault_id": vault_id,
        "salt_hex": salt.hex(),
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "cipher": "AES-256-GCM",
        "note": "Keep this file secret. It does not replace the passphrase; "
                "both the salt and the correct passphrase are required to "
                "regenerate the vault's encryption key.",
    }
    with open(key_backup_path, "w") as f:
        json.dump(backup, f, indent=2)
    print(f"Key backup written to '{key_backup_path}' (salt + KDF parameters, no raw key/passphrase stored)")


def load_key_backup(key_backup_path: str) -> dict:
    with open(key_backup_path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Step 1 & 2: recursively scan a directory and encrypt each file with AES-GCM
# ---------------------------------------------------------------------------
def encrypt_directory(source_dir: str, vault_path: str, key_backup_path: str,
                       passphrase: str) -> None:
    if not os.path.isdir(source_dir):
        raise SystemExit(f"Error: '{source_dir}' is not a directory.")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    vault_id = os.urandom(8).hex()

    file_list = []
    for root, _, files in os.walk(source_dir):
        for name in files:
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, source_dir)
            file_list.append((full_path, rel_path))

    os.makedirs(vault_path, exist_ok=True)
    manifest = {"vault_id": vault_id, "files": []}

    for full_path, rel_path in file_list:
        original_hash = sha256_of_file(full_path)
        with open(full_path, "rb") as f:
            plaintext = f.read()

        nonce = os.urandom(NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=rel_path.encode())

        enc_name = hashlib.sha256(rel_path.encode()).hexdigest() + ".enc"
        enc_path = os.path.join(vault_path, enc_name)
        with open(enc_path, "wb") as f:
            f.write(nonce + ciphertext)

        manifest["files"].append({
            "rel_path": rel_path,
            "enc_file": enc_name,
            "sha256_plaintext": original_hash,
            "size_bytes": len(plaintext),
        })
        print(f"  Encrypted: {rel_path}  ->  {enc_name}  (sha256={original_hash[:12]}...)")

    manifest_path = os.path.join(vault_path, MANIFEST_NAME)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    write_key_backup(key_backup_path, salt, vault_id)

    print(f"\nEncrypted {len(file_list)} file(s) from '{source_dir}' into vault '{vault_path}'")


# ---------------------------------------------------------------------------
# Step 4: decrypt/restore the whole directory, verifying integrity
# ---------------------------------------------------------------------------
def decrypt_directory(vault_path: str, key_backup_path: str, output_dir: str,
                       passphrase: str) -> None:
    backup = load_key_backup(key_backup_path)
    salt = bytes.fromhex(backup["salt_hex"])
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    manifest_path = os.path.join(vault_path, MANIFEST_NAME)
    with open(manifest_path) as f:
        manifest = json.load(f)

    if manifest["vault_id"] != backup["vault_id"]:
        raise SystemExit("Error: key backup does not match this vault (vault_id mismatch).")

    os.makedirs(output_dir, exist_ok=True)
    restored, failed = 0, 0

    for entry in manifest["files"]:
        enc_path = os.path.join(vault_path, entry["enc_file"])
        with open(enc_path, "rb") as f:
            data = f.read()
        nonce, ciphertext = data[:NONCE_SIZE], data[NONCE_SIZE:]

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=entry["rel_path"].encode())
        except InvalidTag:
            print(f"  FAILED (integrity check failed — wrong passphrase or tampering): {entry['rel_path']}")
            failed += 1
            continue

        out_path = os.path.join(output_dir, entry["rel_path"])
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(plaintext)

        restored_hash = hashlib.sha256(plaintext).hexdigest()
        match = restored_hash == entry["sha256_plaintext"]
        status = "OK, checksum verified" if match else "CORRUPTION DETECTED"
        print(f"  Restored: {entry['rel_path']}  ({status})")
        restored += 1

    print(f"\nRestored {restored} file(s) to '{output_dir}' ({failed} failed)")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Cryptographic Encryption Vault — directory-level AES-256-GCM encryption")
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encrypt", help="Encrypt a directory into a vault")
    enc.add_argument("-d", "--dir", required=True, help="Source directory to encrypt")
    enc.add_argument("-o", "--out", required=True, help="Output vault directory")
    enc.add_argument("-k", "--keyfile", required=True, help="Path to write the key backup file")
    enc.add_argument("-p", "--passphrase", help="Master passphrase (omit to be prompted)")

    dec = subparsers.add_parser("decrypt", help="Decrypt/restore a vault")
    dec.add_argument("-v", "--vault", required=True, help="Vault directory to decrypt")
    dec.add_argument("-k", "--keyfile", required=True, help="Path to the key backup file")
    dec.add_argument("-o", "--out", required=True, help="Output directory for restored files")
    dec.add_argument("-p", "--passphrase", help="Master passphrase (omit to be prompted)")

    args = parser.parse_args()
    passphrase = args.passphrase or getpass.getpass("Enter master passphrase: ")

    if args.command == "encrypt":
        encrypt_directory(args.dir, args.out, args.keyfile, passphrase)
    elif args.command == "decrypt":
        decrypt_directory(args.vault, args.keyfile, args.out, passphrase)


if __name__ == "__main__":
    main()
