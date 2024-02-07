from flask import request, jsonify
#from boot import app, genesis_block
from flask import Blueprint, g

from node import Node, n

#we have to define bootstrap here because we cant import it from the main program: there we import bp and it would create a circular import
bootstrap = Node(0)
node = Node()

bp = Blueprint('endpoints', __name__)


@bp.route('/register_node', methods=['POST'])
def register_node():
    global node
    node.id = len(bootstrap.node_ring)
    print(node.id)
    data = request.get_json()
    node_pubkey = node.wallet.public_key
    node_ipaddr = data['ip_address']
    node_port = data['port']
    bootstrap.add_to_ring(node_ipaddr, node_pubkey, node_port)
    return jsonify({"message": "Node registered successfully"}), 200


@bp.route('/update_node_ring', methods=['POST'])
def update_node_ring():
    global node
    data = request.get_json()
    node_ring = data['node_ring']
    node.node_ring = node_ring
    print(node.node_ring)  
    return jsonify({"message": "Node ring updated successfully"}), 200