import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time
from typing import List, Any
from typing import Optional
import hashlib
from wallet import Wallet
from transaction import Transaction
from block import Block

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