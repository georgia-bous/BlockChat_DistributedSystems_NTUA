#import socket
#import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time
from typing import List, Any
from typing import Optional
import hashlib

from classes import Node, Block, Transaction, node_ring

host = '127.0.0.1'
host_port = 12345 
#different for each node
ip_addr = '127.0.0.1'
port = 12345

capacity=5
n=2
#nodes_ipaddr=[]
#nodes_pubkeys=[]
#ports=[]
#id=0
#wallet = None
#transactions=[]
nonce=0

is_bootstrap = True

#node_ring=[]
'''
bootstrap = None

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


from flask import Flask
from flask_restful import Api, Resource
import requests
from threading import Thread
from endpoints import bp, bootstrap

app = Flask(__name__)
api = Api(app)
genesis_block = None

app.register_blueprint(bp)

def main():
    if is_bootstrap :
        bootstrap.add_to_ring(host, bootstrap.wallet.public_key, host_port)
        genesis_block = Block(index=0, transactions=[], validator=0, previous_hash='1')
        #should create a loop or sth to add n-1 nodes
        #create_transaction(genesis_block, 0, node.wallet.public_key, 'coins', 1000*n)
        
    else : 
        global ip_addr
        global port
        #global host
        #global host_port
        node = Node(len(node_ring))
        my_data = {
            'public_key': node.wallet.public_key,
            'ip_address': ip_addr,
            'port': port
        }
        bootstrap_url = f'http://{host}:{host_port}/register_node'
        response = requests.post(bootstrap_url, json=my_data)
        print(f"Bootstrap node responded: {response.json()}")

def run_flask_app():
    global ip_addr
    global port
    app.run(host= ip_addr, port=port, debug=False)

if __name__ =="__main__":
    flask_thread = Thread(target=run_flask_app)
    flask_thread.start()
    main()