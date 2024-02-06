from typing import List, Any
import time
import hashlib

class Block:
    def __init__(self, index: int, transactions: List[Any], validator: str, previous_hash: str):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.validator = validator
        self.previous_hash = previous_hash
        self.current_hash = self.calculate_hash()

    def calculate_hash(self):
        """
        Calculates the hash of the block using SHA-256 algorithm.
        """
        block_string = f"{self.index}{self.timestamp}{self.transactions}{self.validator}{self.previous_hash}".encode()
        return hashlib.sha256(block_string).hexdigest()


    def add_transaction(self, transaction):
        self.transactions.append(transaction)