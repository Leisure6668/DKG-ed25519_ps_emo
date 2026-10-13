from dataclasses import dataclass
#消息结构
@dataclass
class PublicCommitmentMessage:
    sender_id:int
    commitments:list[int]

@dataclass
class PrivateShareMessage:
    sender_id:int
    receiver_id:int
    share:int
