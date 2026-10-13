"""stage05_ed25519/test_ed25519.py"""

import pytest
from ed25519_modle import get_public_key_bytes, private_key_from_seed, sign, verify


# 固定 32 字节测试 seed
TEST_SEED = b"\x01" * 32
TEST_MESSAGE = b"hello ed25519 dkg"


def test_seed_length_validation():
    # 正确长度 32
    priv = private_key_from_seed(TEST_SEED)
    assert priv is not None

    # 非 32 字节必须抛出 ValueError
    with pytest.raises(ValueError, match="32字节"):
        private_key_from_seed(b"\x01" * 31)

    with pytest.raises(ValueError, match="32字节"):
        private_key_from_seed(b"\x01" * 33)

    # 错误类型拦截
    with pytest.raises(TypeError):
        private_key_from_seed("not_bytes")  # type: ignore


def test_sign_and_verify_success():
    pub_bytes = get_public_key_bytes(TEST_SEED)
    assert len(pub_bytes) == 32

    signature = sign(TEST_MESSAGE, TEST_SEED)
    assert len(signature) == 64

    # 正常验签通过
    assert verify(TEST_MESSAGE, signature, pub_bytes) is True


def test_tampered_message_fails():
    pub_bytes = get_public_key_bytes(TEST_SEED)
    signature = sign(TEST_MESSAGE, TEST_SEED)

    # 修改消息后验证必须返回 False
    tampered_msg = b"hello ed25519 dkg!"
    assert verify(tampered_msg, signature, pub_bytes) is False


def test_tampered_signature_fails():
    pub_bytes = get_public_key_bytes(TEST_SEED)
    signature = sign(TEST_MESSAGE, TEST_SEED)

    # 篡改签名的某一个字节
    tampered_sig = bytearray(signature)
    tampered_sig[0] ^= 0x01
    assert verify(TEST_MESSAGE, bytes(tampered_sig), pub_bytes) is False

    # 签名长度异常返回 False
    short_sig = signature[:-1]
    assert verify(TEST_MESSAGE, short_sig, pub_bytes) is False


def test_tampered_public_key_fails():
    pub_bytes = get_public_key_bytes(TEST_SEED)
    signature = sign(TEST_MESSAGE, TEST_SEED)

    # 使用另一个私钥的公钥来验签必须返回 False
    other_seed = b"\x02" * 32
    other_pub_bytes = get_public_key_bytes(other_seed)
    assert verify(TEST_MESSAGE, signature, other_pub_bytes) is False