
from dataclasses import dataclass
import hashlib
import secrets
from py_ecc.optimized_bls12_381 import (
    G1,
    G2,
    add,
    curve_order,
    eq,
    is_inf,
    multiply,
    pairing,
)

Q = curve_order
PS_HASH_DOMAIN = b"DKG-DEMO-PS-MSG-V1:"


@dataclass(frozen=True)
class PsPrivateKey:
    x: int
    y1: int


@dataclass(frozen=True)
class PsPublicKey:
    X: tuple
    Y1: tuple

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PsPublicKey):
            return NotImplemented
        return bool(eq(self.X, other.X) and eq(self.Y1, other.Y1))


@dataclass(frozen=True)
class PsSignature:
    A: tuple
    B: tuple

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PsSignature):
            return NotImplemented
        return bool(eq(self.A, other.A) and eq(self.B, other.B))


def hash_message_to_scalar(message: bytes) -> int:
    """将消息哈希映射为标量 m = H(message) mod q。"""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message 必须是 bytes 类型")
    digest = hashlib.sha256(PS_HASH_DOMAIN + bytes(message)).digest()
    return int.from_bytes(digest, byteorder="big") % Q


def keygen(x: int, y1: int) -> tuple[PsPrivateKey, PsPublicKey]:
    """根据标量 (x, y1) 生成 PS 私钥与 G2 上的公钥 (X, Y1)。"""
    x_mod = x % Q
    y1_mod = y1 % Q
    if x_mod == 0 or y1_mod == 0:
        raise ValueError("私钥标量 x 和 y1 在模 q 下不能为 0")

    priv = PsPrivateKey(x=x_mod, y1=y1_mod)
    pub = PsPublicKey(
        X=multiply(G2, x_mod),
        Y1=multiply(G2, y1_mod),
    )
    return priv, pub


def sign(message: bytes, private_key: PsPrivateKey) -> PsSignature:
    """对单条消息生成随机化的 PS 签名 (A, B)。

    m = H(message) mod q
    A = r * G1
    B = r * ((x + y1 * m) * G1)
    """
    m = hash_message_to_scalar(message)

    # 随机选择非零标量 r in [1, q - 1]
    r = secrets.randbelow(Q - 1) + 1

    A = multiply(G1, r)
    exponent = (private_key.x + private_key.y1 * m) % Q
    B = multiply(multiply(G1, exponent), r)
    return PsSignature(A=A, B=B)


def verify(
    message: bytes, signature: PsSignature, public_key: PsPublicKey
) -> bool:
    """使用双线性配对验证 PS 签名: e(B, G2) == e(A, X + m * Y1)。"""
    if not isinstance(message, (bytes, bytearray)):
        return False
    if not isinstance(signature, PsSignature) or not isinstance(
        public_key, PsPublicKey
    ):
        return False

    try:
        # PS 签名要求 A 不能是无穷远点（单位元）
        if is_inf(signature.A):
            return False

        m = hash_message_to_scalar(message)

        # 计算 X + m * Y1 (在 G2 上)
        rhs_g2 = add(public_key.X, multiply(public_key.Y1, m))

        # 注意 py_ecc.pairing 的参数顺序为 pairing(G2_point, G1_point)
        lhs = pairing(G2, signature.B)
        rhs = pairing(rhs_g2, signature.A)
        return bool(lhs == rhs)
    except Exception:
        return False