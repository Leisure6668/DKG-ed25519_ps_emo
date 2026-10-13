import sys

from py_ecc.optimized_bls12_381 import add,curve_order
from s3_local_simulator.message_bus import InMemoryMessageBus
from s4_bls12_381 import participant
from s4_bls12_381.participant import BlsParticipant

class BlsDkgSimulator:
    def __init__(self,participants :int=5,threshold:int = 3)->None:
        self.participants = participants
        self.threshold = threshold
        self.q=curve_order
        self.bus = InMemoryMessageBus()
        self.nodes=[
            BlsParticipant(node_id=i,threshold = threshold,participants= participants)
            for i in range(1,participants+1)
        ]

    def run(self) -> dict[int,int]:
        for node in self.nodes:
            node.broadcast_commitments(self.bus)
        for node in self.nodes:
            node.send_private_shares(self.bus)
        return{
                node.node_id:node.verify_and_aggregate(self.bus)
                for node in self.nodes
            }

    def get_group_secret(self) ->int:
        return  sum(node.coefficients[0] for node in self.nodes) % self.q

    def get_group_commitment(self) ->tuple:
        group_point = None
        for msg in self.bus.public_message:
            c_0 = msg.commitments[0]
            group_point = c_0 if group_point is None else add(group_point , c_0)
        return group_point