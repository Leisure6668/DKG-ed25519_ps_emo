import secrets
from py_ecc.optimized_bls12_381 import *
from s1_shamir.polynomial import *
from s3_local_simulator.message_bus import *
from s3_local_simulator.models import (PublicCommitmentMessage,PrivateShareMessage)
from s4_bls12_381.commitment import make_commitments,verify_share

class BlsParticipant:

    def  __init__(self,node_id:int,threshold:int,participants:int) ->None:
        if node_id <=0:
            raise ValueError(f"节点编号必须从1开始：{node_id}")
        self.node_id = node_id
        self.threshold = threshold
        self.participants = participants
        self.q = curve_order

        self.coefficients =[secrets.randbelow(self.q) for _ in range(threshold) ]
        self.final_share:int | None = None

    def broadcast_commitments(self,bus:InMemoryMessageBus)->None:
        commitments = make_commitments(self.coefficients)
        bus.broadcast(
            PublicCommitmentMessage(
                sender_id=self.node_id,commitments=commitments,
            )
        )

    def send_private_shares(self, bus: InMemoryMessageBus) -> None:
        for target_id in range(1, self.participants + 1):
            share_val = evaluate_polynomial(
                    self.coefficients, x=target_id, p=self.q)
            bus.send_private(
                    PrivateShareMessage(
                        sender_id=self.node_id,
                        receiver_id=target_id,
                        share=share_val,
                    ))
    def verify_and_aggregate(self,bus:InMemoryMessageBus)->int:
        commitments_map={
            msg.sender_id:msg.commitments for msg in bus.public_message
        }

        for sender_id in range(1,self.participants+1):
            if sender_id not in commitments_map:
                raise ValueError(f"缺少来自节点{sender_id}的公开承诺")

        received_shares = bus.private_messages_for(self.node_id)
        if len(received_shares) != self.participants:
            raise ValueError(f"私有份额数量不足：应为{self.participants},实收{len(received_shares)}")
        total_share = 0
        for msg in received_shares:
            commitments = commitments_map[msg.sender_id]

            if not verify_share(msg.share,self.node_id,commitments):
                raise ValueError(f"节点{self.node_id}收到来自节点{msg.sender_id}的非法篡改份额")

            total_share = (total_share +msg.share) %self.q

        self.final_share = total_share
        return self.final_share