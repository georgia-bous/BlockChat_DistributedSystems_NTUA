import hashlib
from typing import Optional

# Maybe transaction adresses should not be string, but actualy Key objects. From key objects we can extract the string easily.
class Transaction:
    def __init__(self, sender_address: str, receiver_address: str, type_of_transaction: str, nonce: int, amount: Optional[float], message: Optional[str]):
        self.sender_address = sender_address
        self.receiver_address = receiver_address
        self.type_of_transaction = type_of_transaction
        self.amount = amount
        self.message = message
        self.nonce = nonce
        self.transaction_id = self.calculate_transaction_id()

    def calculate_transaction_id(self):
        """
        Calculates the hash of the transaction using SHA-256 algorithm.
        """
        if self.message is None:
            tx_content = f"{self.sender_address}{self.receiver_address}{self.type_of_transaction}{self.amount}{self.nonce}".encode()
        else:
            tx_content = f"{self.sender_address}{self.receiver_address}{self.type_of_transaction}{self.message}{self.nonce}".encode()
        return hashlib.sha256(tx_content).hexdigest()
    
    def as_dict(self):
        result = {}
        result['sender_address'] = self.sender_address
        result['receiver_adress'] = self.receiver_address
        result['type'] = self.type_of_transaction
        result['amount'] = self.amount
        result['message'] = self.message
        result['nonce'] = self.nonce
        result['hash'] = self.transaction_id
        return result