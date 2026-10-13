from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def private_key_from_seed(seed:bytes) -> ed25519.Ed25519PrivateKey:
    if not isinstance(seed, (bytes,bytearray)):
        raise TypeError(f"seed 必须是bytes类型，实收type{seed}")
    if len(seed) != 32:
        raise ValueError(f"seed必须严格为32字节，当前长度：{len(seed)}")
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(seed))

def get_public_key_bytes(seed:bytes) -> bytes:
    priv_key = private_key_from_seed(seed)
    return priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

def sign(message:bytes,seed:bytes)->bytes:
    if not isinstance(message, (bytes,bytearray)):
        raise TypeError(f"message必须为bytes类型，实收{type(message)}")

    priv_key = private_key_from_seed(seed)
    signature = priv_key.sign(message)

    if len(signature) !=64:
        raise RuntimeError(f"Ed25519签名长度异常：{len(signature)}字节")
    return signature

def verify(message:bytes,signature:bytes,public_key_bytes:bytes)->bool:
    if not isinstance(message, (bytes,bytearray)):
        return False
    if not isinstance(signature, (bytes,bytearray)) or len(signature) != 64:
        return False
    if not isinstance(public_key_bytes, (bytes,bytearray)) or len(public_key_bytes) !=64:
        return False
    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_key_bytes))
        pub_key.verify(bytes(signature),bytes(message))
        return True
    except (InvalidSignature,ValueError):
        return False

