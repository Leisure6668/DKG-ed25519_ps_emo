from s3_local_simulator.models import PrivateShareMessage, PublicCommitmentMessage

class InMemoryMessageBus:
    def __init__(self)->None:
        self.public_message:list[PublicCommitmentMessage]=[]
        self.private_message:list[PrivateShareMessage]=[]

    def broadcast(self,message:PublicCommitmentMessage)->None:
        self.public_message.append(message)

    def send_private(self,message:PrivateShareMessage)->None:
        self.private_message.append(message)

    def public_messages(self) -> list[PublicCommitmentMessage]:
        return list(self.public_message)

    def private_messages_for(self,receiver_id:int)->list[PrivateShareMessage]:
        return [msg for msg in self.private_message if msg.receiver_id == receiver_id]