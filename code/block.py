from typing import List, Any
import time
import hashlib

class Block:
    def __init__(self, index: int, transactions: List[Any] = [], validator: str = None, previous_hash: str = None, t=None, hash=None):
        self.index = index
        self.timestamp = time.time() if t is None else t
        self.transactions = transactions
        self.validator = validator
        self.previous_hash = previous_hash
        self.current_hash = hash if hash else self.calculate_hash()
        if hash and self.current_hash != hash:
            print('DIFFERENT HASHES')
            print(self.as_serialised_dict())

    def calculate_hash(self):
        """
        Calculates the hash of the block using SHA-256 algorithm.
        """
        block_string = f"{self.index}{self.timestamp}{self.transactions}{self.validator}{self.previous_hash}".encode()
        return hashlib.sha256(block_string).hexdigest()


    def add_transaction(self, transaction):
        self.transactions.append(transaction)

    def as_serialised_dict(self):
        result = {}
        result['index'] = self.index
        result['timestamp'] = self.timestamp
        result['transactions'] = [trans.as_serialised_dict() for trans in self.transactions]
        result['validator'] = self.validator
        result['previous_hash'] = self.previous_hash
        result['current_hash'] = self.current_hash

        return result