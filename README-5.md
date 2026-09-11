# Cryptographic Encryption Vault

A secure Python vault script that encrypts and decrypts **whole
directories** (recursively) using AES-256-GCM with a passphrase-derived
key, plus a key-file backup for recoverability.

## Objective

Build a multi-file directory encryption tool with key management best
practices.

## How it works

1. **Recursive directory scan** — walks the source directory (including
   subfolders) and collects every file to encrypt.
2. **AES-256-GCM encryption** — each file is encrypted individually with
   its own random nonce, using a 256-bit key derived from a master
   passphrase via PBKDF2-HMAC-SHA256 (390,000 iterations) with a random
   per-vault salt. AES-GCM provides authenticated encryption, so
   tampering or a wrong passphrase is detected automatically.
3. **Key management** — the passphrase itself is never stored anywhere.
   A `vault.key` backup file stores only the random salt, KDF parameters,
   and a vault ID — recovering the vault still requires the correct
   passphrase *and* this file (defense in depth: neither alone is enough).
4. **Manifest + integrity verification** — an encrypted-file manifest
   records each original file's relative path and a SHA-256 checksum of
   its plaintext. On restore, each file's checksum is recomputed and
   compared, so any corruption is caught immediately.

## Usage

```bash
# Encrypt a whole directory into a vault
python crypto_vault.py encrypt -d my_folder -o my_folder.vault -k vault.key

# Restore it (prompts for the passphrase if -p is omitted)
python crypto_vault.py decrypt -v my_folder.vault -k vault.key -o restored_folder
```

## Verification performed

- ✅ Encrypted a 3-file nested directory (including a subfolder).
- ✅ Restored it into a new directory; `diff -r` confirms the restored
  tree is byte-for-byte identical to the original — no data corruption.
- ✅ Every restored file's SHA-256 checksum matched the pre-encryption
  checksum recorded in the manifest.
- ✅ Attempting to decrypt with the wrong passphrase correctly fails the
  AES-GCM integrity check on every file, and writes no output.

## Example output

```
=== Encrypting the directory ===
  Encrypted: notes.txt  ->  e39538e7...c5dce6.enc  (sha256=af70bbf54575...)
  Encrypted: subfolder/config.json  ->  5e47cf51...4d7723cb.enc  (sha256=ef4de58f215e...)
  Encrypted: subfolder/secret.txt  ->  499b8832...7a500a96.enc  (sha256=c4cb488a2d2a...)
Key backup written to 'vault.key' (salt + KDF parameters, no raw key/passphrase stored)

Encrypted 3 file(s) from 'test_data' into vault 'test_data.vault'

=== Decrypting/restoring the vault ===
  Restored: notes.txt  (OK, checksum verified)
  Restored: subfolder/config.json  (OK, checksum verified)
  Restored: subfolder/secret.txt  (OK, checksum verified)

Restored 3 file(s) to 'restored_data' (0 failed)
```

## Project structure

```
crypto-vault/
├── crypto_vault.py   # main encrypt/decrypt CLI
└── README.md
```

## Key management notes

- Encrypted filenames are SHA-256 hashes of their original relative path,
  so the vault directory listing doesn't leak original filenames.
- The manifest (`__vault_manifest__.json`) stores relative paths and
  plaintext checksums needed to restore and verify the vault — it is
  stored inside the vault directory alongside the encrypted files.
- `vault.key` should be kept separate from the vault itself (e.g. a
  different storage location) as a best practice, since together with
  the correct passphrase it enables decryption.
