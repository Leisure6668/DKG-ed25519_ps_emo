import pytest
from field import add_mod, inv_mod, mul_mod
from itertools import combinations
from polynomial import evaluate_polynomial
from shamir import (
    generate_polynomial,
    generate_shares,
    lagrange_coefficient_at_zero,
    reconstruct_secret,
)

P = 2089
SECRET = 1234
THRESHOLD = 3
PARTICIPANTS = 5

def test_field_propeerties():
    assert add_mod(-5,2,P) ==2086
    assert (-10) % P == 2079

    # 模逆元乘积为 1
    inv = inv_mod(42, P)
    assert mul_mod(42, inv, P) == 1

    # 0 没有逆元
    with pytest.raises(ZeroDivisionError):
        inv_mod(0, P)
    with pytest.raises(ZeroDivisionError):
        inv_mod(P, P)


def test_polynomial_evaluation():
    # f(x) = 1234 + 10x + 5x^2 mod 2089
    coeffs = [SECRET, 10, 5]

    # x = 0 时必须严格等于秘密
    assert evaluate_polynomial(coeffs, 0, P) == SECRET

    # x = 2: 1234 + 20 + 20 = 1274
    assert evaluate_polynomial(coeffs, 2, P) == 1274


def test_shamir_full_flow():
    # 1. 生成度数为 threshold - 1 的多项式
    coeffs = generate_polynomial(SECRET, THRESHOLD, P)
    assert evaluate_polynomial(coeffs, 0, P) == SECRET

    # 2. 生成 5 个参与方份额，节点编号从 1 开始
    shares = generate_shares(coeffs, PARTICIPANTS, P)
    assert len(shares) == 5
    assert [x for x, _ in shares] == [1, 2, 3, 4, 5]

    # 3. 任意 3 个份额都必须能恢复同一个秘密
    for subset in combinations(shares, THRESHOLD):
        recovered = reconstruct_secret(list(subset), THRESHOLD, P)
        assert recovered == SECRET

    # 4. 任意 2 个份额必须直接拒绝，抛出异常
    for subset in combinations(shares, THRESHOLD - 1):
        with pytest.raises(ValueError, match="份额数量不足"):
            reconstruct_secret(list(subset), THRESHOLD, P)

    # 5. 重复节点编号直接拒绝
    duplicated_shares = [shares[0], shares[0], shares[1]]
    with pytest.raises(ValueError, match="包含重复节点编号"):
        reconstruct_secret(duplicated_shares, THRESHOLD, P)