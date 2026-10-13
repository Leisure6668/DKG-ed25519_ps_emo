"""stage03_local_simulator/test_simulator.py"""

from itertools import combinations
from pathlib import Path
import sys
import pytest
from s1_shamir.shamir import reconstruct_secret
from s3_local_simulator.models import PrivateShareMessage
from s3_local_simulator.simulator import DkgSimulator


def test_dkg_simulation_flow():
    sim = DkgSimulator(participants=5, threshold=3)
    final_shares = sim.run()

    assert len(final_shares) == 5

    expected_secret = sim.get_group_secret()
    shares_list = list(final_shares.items())

    # 任意 3 个节点最终份额恢复出相同的群体秘密
    for subset in combinations(shares_list, 3):
        recovered = reconstruct_secret(list(subset), threshold=3, p=sim.q)
        assert recovered == expected_secret

    # 2 个份额被拒绝
    for subset in combinations(shares_list, 2):
        with pytest.raises(ValueError, match="份额数量不足"):
            reconstruct_secret(list(subset), threshold=3, p=sim.q)


def test_tampered_private_share_detected():
    sim = DkgSimulator(participants=5, threshold=3)

    for node in sim.nodes:
        node.broadcast_commitments(sim.bus)
    for node in sim.nodes:
        node.send_private_shares(sim.bus)

    # 篡改私有份额
    for idx, msg in enumerate(sim.bus.private_message):
        if msg.receiver_id == 1 and msg.sender_id != 1:
            sim.bus.private_message[idx] = PrivateShareMessage(
                sender_id=msg.sender_id,
                receiver_id=1,
                share=(msg.share + 1) % sim.q,
            )
            break

    # 校验必须被拦截
    with pytest.raises(ValueError, match="非法篡改份额"):
        sim.nodes[0].verify_and_aggregate(sim.bus)