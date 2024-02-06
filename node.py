import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time
from typing import List, Any
from typing import Optional
import hashlib

host='127.0.0.1'
port=12345

capacity=5
n=2
nodes_ipaddr=[]
nodes_pubkeys=[]
ports=[]
id=0
wallet = None
#transactions=[]
nonce=0

is_bootstrap = True



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

    def generate_wallet():
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
    


class Node:
    def __init__(self, id:int):
        self.id = id
        wallet = Wallet()
        self.ring = []  

    def add_to_ring():  
'''
def bootstrap_recv():

def coin_sending():

def mess_sending():

def broadcast():
'''
def create_transaction(current_block, sender_address, receiver_address, type_of_transaction, amount=0, message=''):
    global nonce
    transaction = Transaction(sender_address, receiver_address, type_of_transaction, amount, message)
    current_block.transactions.append(transaction)
    nonce+= 1
'''
def start_server():
    global host
    global port
    global wallet
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((host, port))
    server_sock.listen()
    print(f"Listening for connections on {host}:{port}...")

    conn, addr = server_sock.accept()
    print(f"Connected by {addr}")
    node_id=len(nodes_ipaddr)
    nodes_ipaddr.append(addr[0])
    ports.append(addr[1])
    data = conn.recv(1024).decode('utf-8')
    nodes_pubkeys.append(data)
    print("Received Public Key:", data)
    conn.send(str(node_id).encode('utf-8'))
    trans_send1000 = Transaction(wallet.public_key, data, 'coins', 1000, '')


def main():
    global host
    global port
    global wallet
    wallet = Wallet()
    print("Public Key:", wallet.public_key)
    print("Private Key:", wallet.private_key)
    print("Coins:", wallet.coins)
    genesis_block= Block(index=0, transactions=[], validator=0, previous_hash='1')
    create_transaction(genesis_block, 0, wallet.public_key, 'coins', 1000*n)
    nodes_ipaddr.append(host)
    ports.append(port)
    nodes_pubkeys.append(wallet.public_key)
    start_server()
'''

from Flask import Flask
from Flask_restful import Api, Resource

app = Flask(__name__)
api = Api(app)
genesis_block = None

def main():
    if is_bootstrap :
        node = Node(0)
        genesis_block = Block(index=0, transactions=[], validator=0, previous_hash='1')
        #create_transaction(genesis_block, 0, node.wallet.public_key, 'coins', 1000*n)
        
    else : 



if __name__ =="__main__":
    #specify address and port for each node
    app.run(debug=True)
    main()