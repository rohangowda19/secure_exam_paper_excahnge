#!/usr/bin/env python3
"""Secure examination-paper exchange demo (RSA-3072, AES-256-GCM)."""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
RSA_BITS = 3072


class ExchangeError(Exception):
    """A package could not be safely verified or decrypted."""


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ExchangeError("Invalid package: expected base64 text.")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ExchangeError("Invalid package: malformed base64 data.") from exc


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(key) -> str:
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def write_private(path: Path, key, password: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(password))
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def make_keys(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for role in ("sender", "recipient"):
        print(f"Choose a strong passphrase for {role}'s private key (you will be asked to confirm).")
        password = getpass.getpass("Passphrase: ").encode()
        if len(password) < 12:
            raise ExchangeError("Use a passphrase of at least 12 characters.")
        confirm = getpass.getpass("Confirm: ").encode()
        if password != confirm:
            raise ExchangeError("Passphrases did not match.")
        private = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
        write_private(folder / f"{role}_private.pem", private, password)
        (folder / f"{role}_public.pem").write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        print(f"Created {role} RSA-{RSA_BITS} keys in {folder}")


def load_private(path: Path, password: str):
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=password.encode())
    except Exception as exc:
        raise ExchangeError(f"Could not load private key {path} (wrong passphrase or invalid key).") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ExchangeError("Expected an RSA private key.")
    return key


def load_public(path: Path):
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except Exception as exc:
        raise ExchangeError(f"Could not load public key {path}.") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ExchangeError("Expected an RSA public key.")
    return key


def encrypt_file(source: Path, package_path: Path, sender_private_path: Path,
                 recipient_public_path: Path, sender_password: str) -> None:
    sender = load_private(sender_private_path, sender_password)
    recipient = load_public(recipient_public_path)
    plaintext = source.read_bytes()
    aes_key, nonce = AESGCM.generate_key(bit_length=256), secrets.token_bytes(12)
    # GCM authenticates the package metadata as associated data as well as the ciphertext.
    metadata = {"version": VERSION, "cipher": "AES-256-GCM", "key_wrap": "RSA-OAEP-SHA256",
                "signature": "RSA-PSS-SHA256", "sender_fingerprint": fingerprint(sender.public_key()),
                "recipient_fingerprint": fingerprint(recipient), "original_filename": source.name,
                "plaintext_size": len(plaintext)}
    aad = canonical(metadata)
    combined = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = combined[:-16], combined[-16:]
    wrapped_key = recipient.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                      algorithm=hashes.SHA256(), label=None))
    unsigned = {"metadata": metadata, "encrypted_key": b64(wrapped_key), "nonce": b64(nonce),
                "ciphertext": b64(ciphertext), "tag": b64(tag)}
    signature = sender.sign(canonical(unsigned), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    package = dict(unsigned, signature=b64(signature))
    package_path.parent.mkdir(parents=True, exist_ok=True)
    package_path.write_text(json.dumps(package, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Encrypted {source} -> {package_path}")


def decrypt_file(package_path: Path, output_path: Path, recipient_private_path: Path,
                 trusted_sender_public_path: Path, recipient_password: str) -> None:
    # Plaintext is held in memory until signature, key unwrap, and GCM checks all pass.
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
        expected = {"metadata", "encrypted_key", "nonce", "ciphertext", "tag", "signature"}
        if not isinstance(package, dict) or set(package) != expected:
            raise ExchangeError("Invalid package: missing or unexpected fields.")
        metadata = package["metadata"]
        if not isinstance(metadata, dict) or metadata.get("version") != VERSION:
            raise ExchangeError("Invalid package: unsupported version or metadata.")
        sender = load_public(trusted_sender_public_path)
        recipient = load_private(recipient_private_path, recipient_password)
        if fingerprint(sender) != metadata.get("sender_fingerprint"):
            raise ExchangeError("Sender key fingerprint does not match the trusted key recorded in the package.")
        if fingerprint(recipient.public_key()) != metadata.get("recipient_fingerprint"):
            raise ExchangeError("This recipient private key does not match the package.")
        unsigned = {k: package[k] for k in ("metadata", "encrypted_key", "nonce", "ciphertext", "tag")}
        try:
            sender.verify(unb64(package["signature"]), canonical(unsigned),
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
        except InvalidSignature as exc:
            raise ExchangeError("Signature verification failed: package may be altered or sender key is wrong.") from exc
        try:
            aes_key = recipient.decrypt(unb64(package["encrypted_key"]), padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        except Exception as exc:
            raise ExchangeError("Session-key recovery failed; check the recipient private key.") from exc
        try:
            plaintext = AESGCM(aes_key).decrypt(unb64(package["nonce"]),
                unb64(package["ciphertext"]) + unb64(package["tag"]), canonical(metadata))
        except (InvalidTag, ValueError) as exc:
            raise ExchangeError("AES-GCM authentication failed; no plaintext was released.") from exc
        if len(plaintext) != metadata.get("plaintext_size"):
            raise ExchangeError("Plaintext size does not match signed metadata.")
    except ExchangeError:
        raise
    except Exception as exc:
        raise ExchangeError("Invalid package: could not parse required content.") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)
    print(f"Verified and decrypted package -> {output_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("keygen", help="Generate encrypted sender and recipient key pairs")
    p.add_argument("--folder", type=Path, required=True)
    p = sub.add_parser("encrypt", help="Encrypt and sign a file for the recipient")
    p.add_argument("--input", type=Path, required=True); p.add_argument("--package", type=Path, required=True)
    p.add_argument("--sender-private", type=Path, required=True); p.add_argument("--recipient-public", type=Path, required=True)
    p = sub.add_parser("decrypt", help="Verify and decrypt a received package")
    p.add_argument("--package", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    p.add_argument("--recipient-private", type=Path, required=True); p.add_argument("--sender-public", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "keygen":
            make_keys(args.folder)
        elif args.command == "encrypt":
            encrypt_file(args.input, args.package, args.sender_private, args.recipient_public,
                         getpass.getpass("Sender private-key passphrase: "))
        else:
            decrypt_file(args.package, args.output, args.recipient_private, args.sender_public,
                         getpass.getpass("Recipient private-key passphrase: "))
        return 0
    except (ExchangeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
