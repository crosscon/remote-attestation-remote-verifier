from hashlib import sha512
from base64 import b64encode


def create_hash(bs: bytes) -> str:
    h = sha512()
    h.update(bs)
    dig = h.digest()
    b64 = b64encode(dig).decode()
    return b64
