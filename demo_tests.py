#!/usr/bin/env python3
"""Run the workshop's end-to-end and rejection demonstrations."""
import base64
import json
import tempfile
from pathlib import Path

import secure_exchange as sx
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    root = Path(__file__).resolve().parent
    sender_dir, recipient_dir = root / "sender", root / "recipient"
    sender_keys, recipient_keys = sender_dir / "keys", recipient_dir / "keys"
    sender_keys.mkdir(parents=True, exist_ok=True)
    recipient_keys.mkdir(parents=True, exist_ok=True)
    demo_password = b"workshop-demo-only-passphrase"
    sender_private = rsa.generate_private_key(public_exponent=65537, key_size=sx.RSA_BITS)
    recipient_private = rsa.generate_private_key(public_exponent=65537, key_size=sx.RSA_BITS)
    sx.write_private(sender_keys / "sender_private.pem", sender_private, demo_password)
    sx.write_private(recipient_keys / "recipient_private.pem", recipient_private, demo_password)
    (sender_keys / "sender_public.pem").write_bytes(sender_private.public_key().public_bytes(
        sx.serialization.Encoding.PEM, sx.serialization.PublicFormat.SubjectPublicKeyInfo))
    (recipient_keys / "recipient_public.pem").write_bytes(recipient_private.public_key().public_bytes(
        sx.serialization.Encoding.PEM, sx.serialization.PublicFormat.SubjectPublicKeyInfo))
    # Public keys are the copies delivered through the assumed trusted exchange.
    (recipient_keys / "trusted_sender_public.pem").write_bytes((sender_keys / "sender_public.pem").read_bytes())
    sample = sender_dir / "exam_paper.txt"
    package_path = sender_dir / "outgoing" / "sample_exam_package.json"
    password = demo_password.decode()
    sx.encrypt_file(sample, package_path, sender_keys / "sender_private.pem",
                    recipient_keys / "recipient_public.pem", password)
    received = recipient_dir / "incoming" / "sample_exam_package.json"
    received.parent.mkdir(parents=True, exist_ok=True)
    received.write_bytes(package_path.read_bytes())
    recovered = recipient_dir / "recovered" / "exam_paper.txt"
    sx.decrypt_file(received, recovered, recipient_keys / "recipient_private.pem",
                    recipient_keys / "trusted_sender_public.pem", password)
    assert recovered.read_bytes() == sample.read_bytes()

    results = ["PASS: authorized recipient recovered byte-identical original file."]
    original = json.loads(package_path.read_text())

    def rejected(label, mutate, priv=recipient_keys / "recipient_private.pem",
                 pub=recipient_keys / "trusted_sender_public.pem"):
        altered = json.loads(json.dumps(original))
        mutate(altered)
        with tempfile.TemporaryDirectory() as tmp:
            pkg, out = Path(tmp) / "tampered.json", Path(tmp) / "must_not_exist.txt"
            pkg.write_text(json.dumps(altered))
            try:
                sx.decrypt_file(pkg, out, priv, pub, password)
            except sx.ExchangeError as e:
                assert not out.exists(), "plaintext file was written on failure"
                return f"PASS: {label} rejected; no plaintext written ({e})."
            raise AssertionError(f"{label} unexpectedly succeeded")

    def flip_b64(d, field):
        raw = bytearray(base64.b64decode(d[field])); raw[0] ^= 1
        d[field] = base64.b64encode(raw).decode()

    results.append(rejected("ciphertext modification", lambda d: flip_b64(d, "ciphertext")))
    results.append(rejected("metadata modification", lambda d: d["metadata"].update(original_filename="changed.txt")))
    results.append(rejected("signature modification", lambda d: flip_b64(d, "signature")))

    wrong_recipient = rsa.generate_private_key(public_exponent=65537, key_size=sx.RSA_BITS)
    wrong_dir = recipient_dir / "wrong_key"
    wrong_dir.mkdir(exist_ok=True)
    sx.write_private(wrong_dir / "wrong_private.pem", wrong_recipient, demo_password)
    results.append(rejected("incorrect recipient private key", lambda d: None,
                            priv=wrong_dir / "wrong_private.pem"))
    other_sender = rsa.generate_private_key(public_exponent=65537, key_size=sx.RSA_BITS)
    other_pub = wrong_dir / "wrong_sender_public.pem"
    other_pub.write_bytes(other_sender.public_key().public_bytes(
        sx.serialization.Encoding.PEM, sx.serialization.PublicFormat.SubjectPublicKeyInfo))
    results.append(rejected("incorrect trusted sender public key", lambda d: None, pub=other_pub))

    second_path = sender_dir / "outgoing" / "sample_exam_package_second.json"
    sx.encrypt_file(sample, second_path, sender_keys / "sender_private.pem",
                    recipient_keys / "recipient_public.pem", password)
    first, second = json.loads(package_path.read_text()), json.loads(second_path.read_text())
    assert package_path.read_bytes() != second_path.read_bytes()
    assert first["nonce"] != second["nonce"]
    results.append("PASS: encrypting the same file twice produced different packages and nonces.")

    report = "Secure Examination-Paper Exchange — demonstration results\n"
    report += "Demo-only private-key passphrase: workshop-demo-only-passphrase\n"
    report += "These demo keys are generated automatically and must not be used for real papers.\n\n"
    report += "\n".join(results) + "\n"
    (root / "demo_results.txt").write_text(report)
    print(report)


if __name__ == "__main__":
    main()
