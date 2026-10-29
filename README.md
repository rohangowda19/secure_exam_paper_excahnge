# Secure Examination-Paper Exchange

## The problem this solves

An exam paper sent through email, a shared drive, or another channel that is not trusted could be read, silently changed, or replaced. Encryption alone hides the content but does not prove who sent it. A checksum alone does not authenticate the sender. This project combines encryption and a digital signature so the coordinator can check the sender and detect changes before receiving any plaintext.

The two people are the **sender (faculty member)** and **recipient (examination coordinator)**. Their public keys are exchanged through a trusted channel. The sender keeps their private key secret; the recipient keeps their own private key secret. On one computer, the `sender/` and `recipient/` folders represent their separate working folders. Keep private keys in the matching folder and do not put them in the exchange folder.

## Cryptographic design

- RSA-3072 separate key pairs, with private keys stored as passphrase-encrypted PKCS#8 PEM files and restrictive file permissions where supported.
- A new random 256-bit AES key and 96-bit nonce for every file encryption. AES-GCM encrypts the paper and authenticates its metadata.
- RSA-OAEP with SHA-256 wraps the AES key to the recipient's public key.
- RSA-PSS with SHA-256 signs the canonical serialization of the complete package: metadata, wrapped key, nonce, ciphertext, and tag.
- During decryption, verify the signature and key identities, unwrap the AES key, then verify/decrypt AES-GCM. The output file is created only after all checks succeed.

## Sequence of events

```mermaid
sequenceDiagram
    actor Faculty as Sender (faculty)
    participant AppS as Sender application
    participant Channel as Untrusted channel / exchange folder
    participant AppR as Recipient application
    actor Coord as Recipient (coordinator)
    Note over Faculty,Coord: Public keys exchanged over a trusted channel beforehand
    Faculty->>AppS: Select examination paper
    AppS->>AppS: Generate fresh AES-256 key and 96-bit nonce
    AppS->>AppS: AES-GCM encrypt paper; authenticate metadata
    AppS->>AppS: RSA-OAEP-SHA256 wrap AES key to recipient public key
    AppS->>AppS: RSA-PSS-SHA256 sign complete package with sender private key
    AppS->>Channel: Send signed encrypted package
    Channel->>AppR: Deliver package (may be observed or modified)
    Coord->>AppR: Request verification and decryption
    AppR->>AppR: Check sender signature and key fingerprints
    AppR->>AppR: Unwrap AES key with recipient private key
    AppR->>AppR: AES-GCM authenticate metadata and ciphertext, then decrypt
    alt All checks succeed
        AppR-->>Coord: Write recovered paper to output folder
    else Any check fails
        AppR-->>Coord: Show clear error; do not write plaintext
    end
```

## Run it

Use Python 3.10 or later. From this folder:

```sh
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
python -m pip install -r requirements.txt
```

Create keys in separate folders. Enter a strong passphrase (at least 12 characters) twice for each private key:

```sh
python secure_exchange.py keygen --folder sender/keys
python secure_exchange.py keygen --folder recipient/keys
```

Exchange only the public key files using the trusted channel, placing a trusted copy of the sender's public key in the recipient folder. Copy the recipient's public key to the sender folder. Then the sender encrypts:

```sh
python secure_exchange.py encrypt --input sender/exam_paper.txt \
  --package sender/outgoing/exam_package.json \
  --sender-private sender/keys/sender_private.pem \
  --recipient-public recipient/keys/recipient_public.pem
```

Transfer `exam_package.json` through the simulated untrusted channel (for example, copy it to `recipient/incoming/`). The recipient verifies and decrypts:

```sh
python secure_exchange.py decrypt --package recipient/incoming/exam_package.json \
  --output recipient/recovered/exam_paper.txt \
  --recipient-private recipient/keys/recipient_private.pem \
  --sender-public recipient/keys/sender_public.pem
```

Do not email or otherwise send private keys. A password protects a private key file at rest; it does not make it safe to share. Back up private keys securely. This demonstration reads the whole paper into memory, so very large files would need a carefully designed streaming format.

## What the protections mean

- **Confidentiality:** AES-GCM encrypts the paper; only the recipient can unwrap its AES key with their private RSA key.
- **Integrity:** RSA-PSS covers every package field, and AES-GCM independently rejects changed encrypted content or metadata.
- **Sender authentication:** the recipient checks the signature with the sender public key obtained through the trusted exchange. If that initial public-key check is weak, an attacker could substitute a key before the exchange.

The signature proves control of the sender's private key, not a real-world identity by itself. Identity depends on the trusted public-key exchange. Metadata and the original filename are signed, but the filename is untrusted input; choose a safe output path yourself as the command does.

## Demonstration and test results

From this folder, run `python demo_tests.py` to recreate the sample exchange and execute all seven checks. It creates encrypted demo private keys under the role folders using a public demo-only passphrase so the run is repeatable; those keys are strictly for this exercise. For any real confidential papers, delete the demo keys and use the interactive `keygen` commands above with strong private passphrases.

The delivered `demo_results.txt` records these cases using independent generated RSA key pairs and sample input:

1. Correct recipient recovers bytes identical to the original.
2. Changed ciphertext is rejected by signature verification.
3. Changed metadata is rejected by signature verification.
4. Changed signature is rejected.
5. Wrong recipient private key is rejected.
6. Wrong trusted sender public key is rejected.
7. Two encryptions of the same input have different package bytes and nonces.

The demo run also leaves a sample encrypted package at `sender/outgoing/sample_exam_package.json` and a successfully recovered sample at `recipient/recovered/exam_paper.txt`.
