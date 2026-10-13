"""stage04_bls12_381/test_stage04.py"""

from itertools import combinations
from pathlib import Path
import sys
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from py_ecc.optimized_bls12_381 import G1, eq,curve_order, multiply
# 复用阶段 1 的拉格朗日恢复算法
from s1_shamir.shamir import reconstruct_secret
from s4_bls12_381.commitment import make_commitments, verify_share
from s4_bls12_381.simulator import BlsDkgSimulator


def test_curve_order_scalar_periodicity():
    """验证标量乘以 G1 具备模 curve_order 的周期性质"""
    scalar = 123456789
    p1 = multiply(G1, scalar)
    p2 = multiply(G1, scalar + curve_order)
    assert eq(p1, p2)


def test_bls_share_verification_and_tampering():
    """验证合法份额通过，篡改份额失败"""
    coeffs = [100, 200, 300]
    commitments = make_commitments(coeffs)

    node_id = 2
    # f(2) = 100 + 200*2 + 300*4 = 1700
    valid_share = (100 + 200 * 2 + 300 * 4) % curve_order

    assert verify_share(valid_share, node_id, commitments) is True

    # 篡改份额必须失败
    tampered_share = (valid_share + 1) % curve_order
    assert verify_share(tampered_share, node_id, commitments) is False


def test_bls_dkg_reconstruction_and_commitment():
    """测试 5 节点 DKG、3 份额恢复以及恢复标量 * G1 == 群体承诺"""
    sim = BlsDkgSimulator(participants=5, threshold=3)
    final_shares = sim.run()

    assert len(final_shares) == 5

    group_secret = sim.get_group_secret()
    group_commitment = sim.get_group_commitment()

    shares_list = list(final_shares.items())

    # 1. 任意 3 个节点利用阶段 1 的拉格朗日函数恢复出相同的主秘密
    for subset in combinations(shares_list, 3):
        recovered = reconstruct_secret(list(subset), threshold=3, p=sim.q)
        assert recovered == group_secret

    # 2. 核心代数验证: 恢复出的主秘密 * G1 必须严格等于群体公开承诺点
    recovered_pubkey = multiply(G1, group_secret)
    assert eq(recovered_pubkey, group_commitment)