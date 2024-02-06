from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time
from typing import List, Any
from typing import Optional
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

class Transaction:
    def __init__(self, sender_address: str, receiver_address: str, type_of_transaction: str, amount: Optional[float] = 0, message: Optional[str] = ''):
        global nonce
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
        tx_content = f"{self.sender_address}{self.receiver_address}{self.type_of_transaction}{self.amount}{self.message}{self.nonce}".encode()
        return hashlib.sha256(tx_content).hexdigest()

class Wallet:
    def __init__(self):
        self.private_key, self.public_key = self.generate_wallet()
        self.coins = 0

    def generate_wallet(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        # Serialize private key
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem_private_key.decode(), pem_public_key.decode()
    
node_ring = []

class Node:
    def __init__(self, id:int):
        self.id = id
        self.wallet = Wallet()
        self.ring = []  

    #bootsrap calls it
    #node ring is going to be a list of json objects, each one containing the attributes of a node
    def add_to_ring(self, ip_addr: str, pubkey:str, port: int):  
        node_info = {
            "ip_addr": ip_addr,
            "pubkey": pubkey,
            "port": port
        }
        # Append the dictionary to the node ring list
        node_ring.append(node_info)