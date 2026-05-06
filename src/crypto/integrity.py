
import hmac
import hashlib
import struct
import time
from typing import NamedTuple


# HMAC output length for SHA-256 is always 32 bytes
MAC_LENGTH = 32  # bytes


class IntegrityError(Exception):
    """Raised when MAC verification fails (possible MITM / tampering)."""


class SignedMessage(NamedTuple):
    """A message bundled with its MAC and metadata."""
    sequence:  int    # monotonically increasing counter (replay protection)
    timestamp: float  # Unix time of creation
    payload:   bytes  # encrypted ciphertext
    mac:       bytes  # HMAC-SHA256 tag (32 bytes)


# ── Core MAC operations ────────────────────────────────────────────────────

def _build_mac_input(sequence: int, payload: bytes) -> bytes:
    """
    Deterministically serialise the fields that must be authenticated.
    Format: big-endian uint64 sequence || payload bytes
    """
    return struct.pack(">Q", sequence) + payload


def compute_mac(hmac_key: bytes, sequence: int, payload: bytes) -> bytes:
    """
    Compute HMAC-SHA256 over (sequence || payload).

    Parameters
    ----------
    hmac_key : 32-byte key from key_derivation.derive_keys()
    sequence : packet sequence number (prevents replay attacks)
    payload  : the ciphertext to protect

    Returns
    -------
    32-byte MAC tag
    """
    if len(hmac_key) < 16:
        raise ValueError("HMAC key too short (minimum 16 bytes)")

    mac_input = _build_mac_input(sequence, payload)
    tag = hmac.new(hmac_key, mac_input, hashlib.sha256).digest()
    return tag


def verify_mac(
    hmac_key: bytes,
    sequence: int,
    payload: bytes,
    received_mac: bytes,
) -> bool:
    """
    Constant-time MAC verification.

    Returns True if the MAC is valid, False otherwise.
    Never raises on a bad MAC — the caller decides how to handle it.
    """
    expected = compute_mac(hmac_key, sequence, payload)
    return hmac.compare_digest(expected, received_mac)


# ── Higher-level helpers ───────────────────────────────────────────────────

def sign_message(
    hmac_key: bytes,
    sequence: int,
    payload: bytes,
) -> SignedMessage:
    """
    Wrap a ciphertext payload in a SignedMessage with MAC + timestamp.
    """
    mac = compute_mac(hmac_key, sequence, payload)
    return SignedMessage(
        sequence=sequence,
        timestamp=time.time(),
        payload=payload,
        mac=mac,
    )


def verify_message(
    hmac_key: bytes,
    msg: SignedMessage,
    max_age_seconds: float = 30.0,
) -> bytes:
    """
    Verify a SignedMessage and return the payload if valid.

    Checks
    ------
    1. MAC integrity  (tamper detection)
    2. Timestamp freshness  (replay-attack detection)

    Raises
    ------
    IntegrityError  on any failure.
    """
    # 1. MAC check
    if not verify_mac(hmac_key, msg.sequence, msg.payload, msg.mac):
        raise IntegrityError(
            f"MAC verification FAILED for sequence={msg.sequence}. "
            "Possible tampering or wrong key."
        )

    # 2. Freshness check
    age = time.time() - msg.timestamp
    if age > max_age_seconds:
        raise IntegrityError(
            f"Message too old ({age:.1f}s > {max_age_seconds}s). "
            "Possible replay attack."
        )

    return msg.payload


def serialize_signed_message(msg: SignedMessage) -> bytes:
    """
    Wire format:
        [8 bytes: sequence (big-endian uint64)]
        [8 bytes: timestamp as double]
        [4 bytes: payload length (big-endian uint32)]
        [N bytes: payload]
        [32 bytes: MAC]
    """
    header = struct.pack(">Qd", msg.sequence, msg.timestamp)
    length = struct.pack(">I", len(msg.payload))
    return header + length + msg.payload + msg.mac


def deserialize_signed_message(data: bytes) -> SignedMessage:
    """Inverse of serialize_signed_message."""
    if len(data) < 8 + 8 + 4 + MAC_LENGTH:
        raise ValueError("Data too short to be a valid SignedMessage")

    offset = 0
    sequence, timestamp = struct.unpack_from(">Qd", data, offset)
    offset += 16

    (payload_len,) = struct.unpack_from(">I", data, offset)
    offset += 4

    payload = data[offset : offset + payload_len]
    offset += payload_len

    mac = data[offset : offset + MAC_LENGTH]

    return SignedMessage(sequence=sequence, timestamp=timestamp,
                         payload=payload, mac=mac)


# ── Quick self-test ────────────────────────────────────────────────────────
if __name__ == "__main__":
    import os

    key = os.urandom(32)
    ciphertext = b"this-is-pretend-ciphertext-from-aes-gcm"

    # Normal flow
    msg = sign_message(key, sequence=1, payload=ciphertext)
    print("=== Integrity Layer (HMAC-SHA256) ===")
    print(f"Sequence  : {msg.sequence}")
    print(f"MAC       : {msg.mac.hex()}")

    recovered = verify_message(key, msg)
    assert recovered == ciphertext
    print("✅ MAC verified OK")

    # Serialization round-trip
    wire = serialize_signed_message(msg)
    msg2 = deserialize_signed_message(wire)
    recovered2 = verify_message(key, msg2)
    assert recovered2 == ciphertext
    print("✅ Serialization round-trip OK")

    # Tamper detection
    tampered = SignedMessage(
        sequence=msg.sequence,
        timestamp=msg.timestamp,
        payload=b"tampered-payload",
        mac=msg.mac,
    )
    try:
        verify_message(key, tampered)
        print("❌ Should have raised IntegrityError!")
    except IntegrityError as e:
        print(f"✅ Tamper correctly detected: {e}")
