from wallet import Wallet
from transaction import Transaction
from typing import List, Any , Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import exceptions

node_ring = []

class Node:
    def __init__(self, id:int, capacity:int, ring_ips:List[Any], ring_ports:List[Any], ring_pks:List[Any], ring_balances:List[Any], ring_stakes:List[Any]):
        '''
        Args:
            ring_ips: ip for every node in the ring
            ring_ports: port for every node in the ring
            ring_pks: publik key of every node in the ring, required to send them coins
            ring_balances: balance of every node
            ring_stakes: stakes currently declared by every node, required to validate transactions
        '''
        self.id = id
        self.wallet = Wallet()
        self.ring_ips = ring_ips
        self.ring_ports = ring_ports
        self.ring_pks = ring_pks
        self.ring_balances = ring_balances
        self.ring_stakes = ring_stakes  
        self.nonce = 0
        self.transactions = []
        self.capacity = capacity 

    def create_transaction(self, sender_address, receiver_address, type_of_transaction, amount:Optional[float], message:Optional[str]):
        transaction = Transaction(sender_address, receiver_address, type_of_transaction, self.nonce, amount, message)
        self.nonce+= 1
        return transaction

    def sign_transaction(self, transaction):
        hash = transaction.transaction_id.encode() # Make the hash digest which is a string, a byte object
        private_key = self.wallet.private_key
        signature = private_key.sign(
            hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return signature
    
    def verify_signature(self, transaction, signature):
        pk = transaction.as_dict()['sender_adress'] # sender_adress is the public key of the sender
        try:
            pk.verify(
                signature,
                transaction.transaction_id.encode(), # In sign_transaction we use the encoded id, so we do the same here
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256())
        except exceptions.InvalidSignature as e:
            print('Wrong signature')
        else: print('OK!')

    #def validate_transaction(self, transaction):

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


n = Node(3,5,[])
t = n.create_transaction('a','b','msg',100,None)
print(t.as_dict())
s = n.sign_transaction(t)
pk = n.wallet.public_key
n.verify_signature(t,s,pk)
    
   # def add_to_ring():  
'''
    def bootstrap_recv():

    def coin_sending():

    def mess_sending():

    def broadcast():
'''