from flask import request, jsonify
#from boot import app, genesis_block
from flask import Blueprint

from node import Node

#we have to define bootstrap here because we cant import it from the main program: there we import bp and it would create a circular import
bootstrap = Node(0)

bp = Blueprint('endpoints', __name__)


@bp.route('/register_node', methods=['POST'])
def register_node():
    data = request.get_json()
    node_pubkey = data['public_key']
    node_ipaddr = data['ip_address']
    node_port = data['port']
    bootstrap.add_to_ring(node_ipaddr, node_pubkey, node_port)
    # Process the incoming data, e.g., store the node's information
    #print(f"Received registration from: {data}")
    # Respond back if needed, for example, with an acknowledgment or node ID
    return jsonify({"message": "Node registered successfully"}), 200