from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dkg_app.kdf import ED25519_SEED_LABEL


def derive_bytes(master_secret:int,label:bytes,length:int)->bytes:

    if isinstance(master_secret,bool) or not isinstance(master_secret,int):
        raise TypeError("master_secret 必须是 int 类型")
    if master_secret < 0 or master_secret >=(1<<256):
        raise ValueError("master_secret 必须落在32字节无符号范围内[0，2^256]")
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("label 必须是 bytes 类型")
    if len(label) == 0:
        raise ValueError("label 不能为空")

    if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
        raise ValueError("length 必须是正整数")

        # 1. 主秘密按 32 字节大端序编码
    ikm = master_secret.to_bytes(32, byteorder="big")

    # 2. 使用 HKDF-SHA256 与独立标签派生目标字节
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=bytes(label),
    )
    return hkdf.derive(ikm)

def derive_ed25519_seed(master_secret:int)->bytes:
    return derive_bytes(
        master_secret = master_secret,
        label = ED25519_SEED_LABEL,
        length = 32
    )