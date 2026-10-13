"""stage06_kdf/test_kdf.py"""

from itertools import combinations
from pathlib import Path
import sys
from cryptography.hazmat.primitives import serialization
from py_ecc.optimized_bls12_381 import curve_order
import pytest

# 将项目根目录与各依赖阶段目录加入 sys.path，兼容直接导入与包导入
CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
for path in (
    CURRENT_DIR,
    ROOT_DIR,
    ROOT_DIR / "s1_shamir",
    ROOT_DIR / "s3_local_simulator",
    ROOT_DIR / "s4_bls12_381",
    ROOT_DIR / "s5_ed25519",
):
    if path.exists() and str(path) not in sys.path:
        sys.path.append(str(path))

from s1_shamir.shamir import reconstruct_secret
from s4_bls12_381.simulator import BlsDkgSimulator
from s5_ed25519.ed25519_modle import private_key_from_seed, sign, verify
from s6_kdf.kdf import (
    ED25519_SEED_LABEL,
    derive_bytes,
    derive_ed25519_seed,
)


def _public_key_bytes_from_seed(seed: bytes) -> bytes:
    """通过阶段 5 的 private_key_from_seed 提取 32 字节原始公钥。"""
    priv_key = private_key_from_seed(seed)
    return priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_kdf_determinism_and_domain_separation():
    master_secret = 9876543210123456789

    # 1. 相同主秘密得到相同 seed
    seed1 = derive_ed25519_seed(master_secret)
    seed2 = derive_ed25519_seed(master_secret)
    assert seed1 == seed2
    assert len(seed1) == 32

    # 2. 不直接把主秘密整数的大端字节当作 Ed25519 seed
    raw_secret_bytes = master_secret.to_bytes(32, byteorder="big")
    assert seed1 != raw_secret_bytes

    # 3. 不同标签得到不同结果
    other_label_out = derive_bytes(
        master_secret=master_secret,
        label=b"DKG-DEMO-OTHER-PURPOSE",
        length=32,
    )
    assert seed1 != other_label_out

    # 4. 不同主秘密得到不同 seed
    different_seed = derive_ed25519_seed(master_secret + 1)
    assert seed1 != different_seed


def test_kdf_invalid_inputs():
    with pytest.raises(ValueError):
        derive_ed25519_seed(-1)

    with pytest.raises(ValueError):
        derive_ed25519_seed(1 << 256)

    with pytest.raises(ValueError):
        derive_bytes(123, b"", 32)

    with pytest.raises(ValueError):
        derive_bytes(123, ED25519_SEED_LABEL, 0)


def test_dkg_to_ed25519_integration():
    """集成测试：任意 3 个 DKG 节点恢复出的 seed 相同，Ed25519 公钥相同。"""
    sim = BlsDkgSimulator(participants=5, threshold=3)
    final_shares = sim.run()
    shares_list = list(final_shares.items())

    reference_seed: bytes | None = None
    reference_pubkey: bytes | None = None
    message = b"dkg stage06 integration test"

    for subset in combinations(shares_list, 3):
        # 1. 从当前 3 个节点的份额恢复主秘密
        recovered_secret = reconstruct_secret(
            list(subset), threshold=3, p=curve_order
        )

        # 2. 派生 Ed25519 种子与公钥
        seed = derive_ed25519_seed(recovered_secret)
        pubkey = _public_key_bytes_from_seed(seed)

        if reference_seed is None:
            reference_seed = seed
            reference_pubkey = pubkey
        else:
            # 任意 3 节点恢复出的 seed 必须相同，Ed25519 公钥必须相同
            assert seed == reference_seed
            assert pubkey == reference_pubkey

        # 3. 验证派生出的密钥可正常完成 Ed25519 签名与验签
        signature = sign(message, seed)
        assert verify(message, signature, pubkey) is True