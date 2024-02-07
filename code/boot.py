from node import Node
from block import Block
from transaction import Transaction

from flask import Flask
from flask_restful import Api, Resource
import requests
from threading import Thread
from endpoints import bp, bootstrap
from flask import g
import argparse
from typing import List, Any , Optional


'''
#for input from cli, not ready yet
# Create the parser
parser = argparse.ArgumentParser(description='Node Configuration')

# Add arguments
parser.add_argument('--ip', type=str, default='127.0.0.1', help='IP address of the node')
parser.add_argument('--port', type=int, help='Port on which the node runs')
parser.add_argument('--capacity', type=int, default=5, help='Capacity of the node')
parser.add_argument('--n', type=int, default=2, help='Number of nodes to add to the network')
parser.add_argument('--is_bootstrap', action='store_true', help='Flag to indicate if the node is a bootstrap node')

# Parse the arguments
args = parser.parse_args()

# Assign the arguments to variables
ip_addr = args.ip
port = args.port
capacity = args.capacity
n = args.n
is_bootstrap = args.is_bootstrap
'''

host = '127.0.0.1'
host_port = 12345 

ip_addr = '127.0.0.1'
port = 12345
is_bootstrap = True
n=3


app = Flask(__name__)
api = Api(app)
genesis_block = None

app.register_blueprint(bp)


def main():
    global n
    if is_bootstrap :
        bootstrap.add_to_ring(host, bootstrap.wallet.public_key, host_port)
        genesis_block = Block(index=0, transactions=[], validator=0, previous_hash='1')
        bootstrap.block = genesis_block
        bootstrap.create_transaction(0, bootstrap.wallet.public_key, 'coins', 1000*n)
        
    else : 
        global ip_addr
        global port
        my_data = {
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