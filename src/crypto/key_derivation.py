import os
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from dataclasses import dataclass

_AES_KEY_LEN   = 32
_CHACHA_KEY_LEN = 32
_HMAC_KEY_LEN  = 32
_TOTAL_LEN     = _AES_KEY_LEN + _CHACHA_KEY_LEN + _HMAC_KEY_LEN

_INFO_MASTER   = b"secure-chat-v1|master-key-material"

@dataclass(frozen=True)
class DerivedKeys:
    aes_key:    bytes
    chacha_key: bytes
    hmac_key:   bytes

def derive_keys(shared_secret: bytes, salt: bytes | None = None, info: bytes = _INFO_MASTER) -> DerivedKeys:
    if not shared_secret:
        raise ValueError("shared_secret must not be empty")

    if salt is None:
        salt = os.urandom(32)

    # استخدام HKDF من مكتبة PyCryptodome
    key_material = HKDF(
        master=shared_secret,
        key_len=_TOTAL_LEN,
        salt=salt,
        hashmod=SHA256,
        context=info
    )

    aes_key    = key_material[:_AES_KEY_LEN]
    chacha_key = key_material[_AES_KEY_LEN : _AES_KEY_LEN + _CHACHA_KEY_LEN]
    hmac_key   = key_material[_AES_KEY_LEN + _CHACHA_KEY_LEN :]

    return DerivedKeys(aes_key=aes_key, chacha_key=chacha_key, hmac_key=hmac_key)

def generate_salt() -> bytes:
    return os.urandom(32)