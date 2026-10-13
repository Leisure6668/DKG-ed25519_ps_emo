"""stage02_feldman/test_feldman.py"""

import pytest
from commitment import make_commitments, verify_share
from vss import generate_vss_shares

P = 2089
Q = 1044
G = 2
SECRET = 123
THRESHOLD = 3
PARTICIPANTS = 5


def test_commitments_generation():
    coeffs = [10, 20, 30]
    commitments = make_commitments(coeffs, G, P)

    assert len(commitments) == 3
    assert commitments[0] == pow(G, 10, P)
    assert commitments[1] == pow(G, 20, P)
    assert commitments[2] == pow(G, 30, P)


def test_vss_valid_shares():
    commitments, shares = generate_vss_shares(
        SECRET, THRESHOLD, PARTICIPANTS, G, P, Q
    )

    assert len(commitments) == THRESHOLD
    assert len(shares) == PARTICIPANTS

    # 每个合法份额都必须验证通过
    for node_id, share in shares:
        assert verify_share(share, node_id, commitments, G, P) is True


def test_tampered_share_fails():
    commitments, shares = generate_vss_shares(
        SECRET, THRESHOLD, PARTICIPANTS, G, P, Q
    )
    node_id, genuine_share = shares[0]

    # 篡改份额值
    tampered_share = (genuine_share + 1) % Q
    assert verify_share(tampered_share, node_id, commitments, G, P) is False


def test_tampered_commitment_fails():
    commitments, shares = generate_vss_shares(
        SECRET, THRESHOLD, PARTICIPANTS, G, P, Q
    )
    node_id, genuine_share = shares[0]

    # 篡改常数项承诺
    tampered_commitments = list(commitments)
    tampered_commitments[0] = (tampered_commitments[0] + 1) % P

    assert (
        verify_share(genuine_share, node_id, tampered_commitments, G, P)
        is False
    )


def test_node_id_starts_from_one():
    commitments, shares = generate_vss_shares(
        SECRET, THRESHOLD, PARTICIPANTS, G, P, Q
    )
    _, share = shares[0]

    # node_id = 0 必须被显式拦截并拒绝
    with pytest.raises(ValueError, match="节点编号从1开始"):
        verify_share(share, 0, commitments, G, P)

    # node_id < 0 也必须被拒绝
    with pytest.raises(ValueError, match="节点编号从1开始"):
        verify_share(share, -1, commitments, G, P)