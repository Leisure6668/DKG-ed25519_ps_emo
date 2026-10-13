"""stage03_local_simulator/simulator.py"""

from message_bus import InMemoryMessageBus
from participant import Participant


class DkgSimulator:
    def __init__(
        self,
        participants: int = 5,
        threshold: int = 3,
        g: int = 12035,
        p: int = 45959,
        q: int = 2089,
    ) -> None:
        self.participants_count = participants
        self.threshold = threshold
        self.g = g
        self.p = p
        self.q = q
        self.bus = InMemoryMessageBus()
        self.nodes = [
            Participant(
                node_id=i,
                threshold=threshold,
                participants=participants,
                g=g,
                p=p,
                q=q,
            )
            for i in range(1, participants + 1)
        ]

    def run(self) -> dict[int, int]:
        """执行完整 DKG 协议交互"""
        # 第一轮：全员广播承诺
        for node in self.nodes:
            node.broadcast_commitments(self.bus)

        # 第二轮：全员点对点发送私有份额
        for node in self.nodes:
            node.send_private_shares(self.bus)

        # 第三轮：全员校验并计算各自的最终份额
        final_shares = {}
        for node in self.nodes:
            final_shares[node.node_id] = node.verify_and_aggregate(self.bus)
        return final_shares

    def get_group_secret(self) -> int:
        """返回所有节点常数项之和作为理论群体秘密: sum(f_i(0)) mod q"""
        return sum(node.coefficients[0] for node in self.nodes) % self.q