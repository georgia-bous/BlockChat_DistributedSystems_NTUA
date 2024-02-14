from flask import request, jsonify
#from boot import app, genesis_block
from flask import Blueprint, g

from node import Node

#we have to define node here because we cant import it from the main program: there we import bp and it would create a circular import
node = Node()

bp = Blueprint('endpoints', __name__)

#node sends to bootstrap its info and he adds it to the ring and sends it the next id
@bp.route('/register_node', methods=['POST'])
def register_node():
    global node
    data = request.get_json()
    node_ipaddr = data['ip_address']
    node_port = data['port']
    node_pubkey = data['pubkey']
    node.add_to_ring(node_ipaddr, node_pubkey, node_port)
    print(node.wallet.coins)
    return jsonify({"message": "Node registered successfully", "id": len(node.node_ring)-1}), 200

#called when bootstrap broadcasts the nodering
@bp.route('/update_node_ring', methods=['POST'])
def update_node_ring():
    global node
    data = request.get_json()
    node_ring = data['node_ring']
    node.node_ring = node_ring
    print(node.node_ring)  
    return jsonify({"message": "Node ring updated successfully"}), 200

#invoked when a transaction is broadcasted, in order to validate it
@bp.route('/receive_transaction', methods=['POST'])
def receive_transaction():
    global node
    transaction_json = request.get_json()
    if node.validate_transaction(transaction_json):
        return jsonify({"message": "Transaction received and validated."}), 200
    else:
        return jsonify({"message": "Transaction validation failed."}), 400