#from node import Node
from block import Block
from transaction import Transaction

from flask import Flask
from flask_restful import Api, Resource
import requests
from threading import Thread
from endpoints import bp, node
from blockchain import Blockchain
from flask import g
import argparse
from typing import List, Any , Optional
from multiprocessing import Process
import logging


user_input = input('Enter the details (host IP, host port, capacity, number of nodes, stake, is bootstrap [yes/no]): ')
# Split the input string by space
inputs = user_input.split(' ')

host = inputs[0].strip()
host_port = int(inputs[1].strip())
capacity = int(inputs[2].strip())
nnodes = int(inputs[3].strip())
stake = int(inputs[4].strip())
is_bootstrap = inputs[5].strip().lower() == 'yes'

ip_addr = '127.0.0.1'
'''
#linux, get ip of each machine
import os
# Command to get the IP address for `eth0` interface
ip_addr = os.popen('ip addr show eth0 | grep "inet\b" | awk \'{print $2}\' | cut -d/ -f1').read().strip()
print(f"IP Address: {ip_addr}")
'''
port = 12346

'''
host = '127.0.0.1'
host_port = 12345 

is_bootstrap = False
nnodes=2
stake = 10
capacity = 3
'''

app = Flask(__name__)
api = Api(app)
genesis_block = None

app.register_blueprint(bp)
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
def main():
    node.capacity = capacity
    node.stake = stake
    node.nnodes = nnodes

    if is_bootstrap :
        node.id = 'id0'
        node.add_to_ring(host, node.wallet.pubkey_serialised(), host_port, node.id)
        first_transaction = node.create_transaction(0, node.wallet.public_key, 'coins', 1000*nnodes)
        genesis_block = Block(index=0, transactions=[first_transaction], validator=0, previous_hash='1')
        node.blockchain.add_block_to_chain(genesis_block) #no validation for genesis

        
    else : 
        global ip_addr
        global port
        my_data = {
            'ip_address': ip_addr,
            'port': port,
            'pubkey': node.wallet.pubkey_serialised()
        }
        bootstrap_url = f'http://{host}:{host_port}/register_node'
        response = requests.post(bootstrap_url, json=my_data)
        response_data=response.json()
        #logging.info(f"Bootstrap node responded: {response_data['message']}")
        node.id = 'id' + str(response_data['id'])
        #logging.info(node.id)
        #node.create_cli()

def run_flask_app():
    global ip_addr
    global port
    #app.debug = True
    app.run(host= ip_addr, port=port, debug=True,use_reloader=False)

if __name__ =="__main__":
    flask_thread = Thread(target=run_flask_app)
    flask_thread.start()
    cli_thread = Thread(target=node.create_cli)
    cli_thread.start()

    #cli_process.join()  # Wait for the CLI process to finish if needed
    main()
