from wallet import Wallet
from transaction import Transaction
from typing import List, Any , Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import exceptions
import requests
import json
import threading
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from block import Block
from blockchain import Blockchain
'''
#keep them stable or find a way to take them from main, cannot import
n=3
stake=10
capacity=5
'''
#we have to either add block attribute to the node or define create_transaction in main
class Node:
    def __init__(self, id:str=None, capacity:int= None, stake= None, nnodes:int= None, block=None, node_ring:List[Any]=[], ring_balances:List[Any]=[], ring_stakes:List[Any]=[]):
        '''
        Args:
            ring_ips: ip for every node in the ring
            ring_ports: port for every node in the ring
            ring_pks: publik key of every node in the ring, required to send them coins
            ring_balances: balance of every node
            ring_stakes: stakes currently declared by every node, required to validate transactions
        '''
        self.id = id
        self.capacity = capacity #do we need capacity and stake as attribute or keep it global variable?
        self.stake = stake 
        self.nnodes = nnodes
        self.wallet = Wallet()
        self.node_ring = []    
        self.block = block     #current block
        self.ring_balances = ring_balances
        self.ring_stakes = ring_stakes  
        self.nonce = 0      # the number of transactions SENT
        self.transactions = []  #keep track the transactions that are gonna be on the next block
        self.blockchain = Blockchain()

    #sender and receiver address are in byte format for hash
    def create_transaction(self, sender_address, receiver_address, type_of_transaction, amount= None, message= None):
        transaction = Transaction(sender_address, receiver_address, type_of_transaction, self.nonce, amount, message)
        if sender_address == 0:  #the first transaction, create transaction is never called
            self.transactions.append(transaction)
            self.nonce+= 1
            self.wallet.coins += 1000*self.nnodes  #do it in a function??
            return transaction
        signature = transaction.sign_transaction(self.wallet.private_key) #byte format
        self.broadcast_transaction(transaction, signature)
        ####
        if len(self.transactions) == self.capacity:
            #execute the transactions in the list for the receivers side
            self.mint_block()
        return transaction


    def send_transaction_to_node(self, node, transaction_json):
        try:
            node_url = f'http://{node["ip_addr"]}:{node["port"]}/receive_transaction'
            response = requests.post(node_url, json=transaction_json, headers={'Content-Type': 'application/json'})

            if response.status_code == 200:
                print(f"Transaction successfully sent to {node['ip_addr']}:{node['port']}")
                return True #the transaction was validated
            else:
                print(f"Failed to send transaction to {node['ip_addr']}:{node['port']}. Response code: {response.status_code}")
                return False #the transaction was not validated
        
        except requests.exceptions.RequestException as e:
            print(f"Error sending transaction to {node['ip_addr']}:{node['port']}: {e}")
            return False


    def broadcast_transaction(self, transaction, signature):
        # Serialize the transaction into JSON
        transaction_data = transaction.as_serialised_dict()
        transaction_data['signature'] = base64.b64encode(signature).decode('utf-8')
        transaction_data['sender_balance'] = self.wallet.coins
        transaction_data['sender_stake'] = self.stake
        transaction_json = json.dumps(transaction_data)

        threads = []
        validation_statuses =[]
        lock = threading.Lock()  #for validation_statuses

        def thread_target(node, transaction_json):
            result = self.send_transaction_to_node(node, transaction_json)
            with lock:
                validation_statuses.append(result)

        # use threads to send the transaction to each node
        for node in self.node_ring:
            if node['pubkey'] != self.wallet.pubkey_serialised():
                print(node['port'])
                t = threading.Thread(target=thread_target, args=(node, transaction_json,))
                threads.append(t)
                t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        if all(validation_statuses):
            print("All nodes validated the transaction.")
            self.transactions.append(transaction)
            self.nonce+= 1
            self.wallet.coins -= transaction.transaction_amount(is_boot_transaction = True)
        else:
            print("One or more nodes failed to validate the transaction.")

    
    def verify_signature(self, transaction_id, sender_address, signature):
        # Decode the sender's public key from PEM format
        sender_public_key_pem = sender_address.encode()  # Ensure it's in bytes
        public_key = serialization.load_pem_public_key(sender_public_key_pem, backend=default_backend())
        
        signature_bytes = base64.b64decode(signature)
        
        # The transaction_id is used as the data that was originally signed
        transaction_id_bytes = transaction_id.encode()  # Ensure it's in bytes for verifying

        try:
            public_key.verify(
                signature_bytes,
                transaction_id_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verification successful.")
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
        

    def validate_transaction(self, transaction_json):
        transaction_dict = json.loads(transaction_json)
        
        ver_sign = self.verify_signature(transaction_dict['transaction_id'], transaction_dict['sender_address'], transaction_dict['signature'])
        if ver_sign == False :
            return False
        
        if transaction_dict['type'] == 'coins':
            if self.node_ring == []:  #its the first transaction from bootstrap to a node, maybe do another if i dont like this one
                coins_needed = transaction_dict['amount']  
            else:
                coins_needed = transaction_dict['amount'] + 0.03 * transaction_dict['amount']  #+3% charge
        elif transaction_dict['type'] == 'message':
            coins_needed = len(transaction_dict['message'])
        else:
            print('Wrong type of transaction.')
            return False
        
        if coins_needed > transaction_dict['sender_balance'] + transaction_dict['sender_stake']:  
            print('Sender does not have enough coins.')
            return False
        else:
            print('Sender okay to send.')
            return True



    #bootsrap calls it
    #node ring is going to be a list of json objects, each one containing the attributes of a node
    def add_to_ring(self, ip_addr: str, pubkey_str:str, port: int): 
        node_info = {
            "ip_addr": ip_addr,
            "pubkey": pubkey_str,
            "port": port
        }
            
        # add node to ring
        self.node_ring.append(node_info)
        
        #convert to byte format
        pubkey = serialization.load_pem_public_key(
            pubkey_str.encode(),  # Convert string to bytes
            backend=default_backend()
        )

        # send coins to the new node (if its not bootstrap)
        if len(self.node_ring)>1:
            self.create_transaction(self.wallet.public_key, pubkey, 'coins', 1000)

        #when all nodes are added, broadcast the node ring
        if len(self.node_ring) == self.nnodes:
            self.broadcast_node_ring()
            #add code to broadcast the blockchain


    #bootstrap calls it
    def broadcast_node_ring(self):
        for node in self.node_ring:
            if node['pubkey'] != self.wallet.pubkey_serialised():
                url = f"http://{node['ip_addr']}:{node['port']}/update_node_ring"
                try:
                    response = requests.post(url, json={"node_ring": self.node_ring})
                    if response.status_code == 200:
                        print(f"Node ring broadcasted successfully to {node['ip_addr']}")
                    else:
                        print(f"Failed to broadcast to {node['ip_addr']}")
                    print(f"Node responded: {response.json()}")
                except Exception as e:
                    print(f"Error broadcasting to {node['ip_addr']}: {e}")


    def mint_block(self):
        #PoS -> validator will create block with transactions and broadcast it -> nodes will validate it and receivers will update their wallets
        return

