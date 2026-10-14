"""stage07_ps/test_ps.py"""

from pathlib import Path
import sys

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
for path in (CURRENT_DIR, ROOT_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from py_ecc.optimized_bls12_381 import G1, Z1, add
from s7_ps.ps import PsSignature, keygen, sign, verify

# 固定测试私钥 (x, y1)
TEST_X = 12345678901234567890
TEST_Y1 = 98765432109876543210
TEST_MESSAGE = b"hello pointcheval-sanders signature"


def test_ps_sign_and_verify_success():
    """测试 1: 正常签名与配对验证通过。"""
    priv, pub = keygen(TEST_X, TEST_Y1)
    sig = sign(TEST_MESSAGE, priv)

    assert verify(TEST_MESSAGE, sig, pub) is True


def test_ps_modified_message_fails():
    """测试 2: 修改消息后配对验证必须失败。"""
    priv, pub = keygen(TEST_X, TEST_Y1)
    sig = sign(TEST_MESSAGE, priv)

    assert verify(b"hello pointcheval-sanders signature!", sig, pub) is False


def test_ps_modified_a_or_b_fails():
    """测试 3: 篡改签名中的 A 或 B 后验证必须失败，无穷远点 A 也必须被拒绝。"""
    priv, pub = keygen(TEST_X, TEST_Y1)
    sig = sign(TEST_MESSAGE, priv)

    # 修改 A: A' = A + G1
    tampered_a = PsSignature(A=add(sig.A, G1), B=sig.B)
    assert verify(TEST_MESSAGE, tampered_a, pub) is False

    # 修改 B: B' = B + G1
    tampered_b = PsSignature(A=sig.A, B=add(sig.B, G1))
    assert verify(TEST_MESSAGE, tampered_b, pub) is False

    # 伪造无穷远点 (Z1, Z1) 必须被拒绝
    trivial_sig = PsSignature(A=Z1, B=Z1)
    assert verify(TEST_MESSAGE, trivial_sig, pub) is False


def test_ps_randomized_signatures_differ_but_both_valid():
    """测试 4: 同一消息两次签名通常不同，但都验证成功。"""
    priv, pub = keygen(TEST_X, TEST_Y1)

    sig1 = sign(TEST_MESSAGE, priv)
    sig2 = sign(TEST_MESSAGE, priv)

    assert sig1 != sig2
    assert verify(TEST_MESSAGE, sig1, pub) is True
    assert verify(TEST_MESSAGE, sig2, pub) is True