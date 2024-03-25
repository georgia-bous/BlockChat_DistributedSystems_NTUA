from flask import request, jsonify
#from boot import app, genesis_block
from flask import Blueprint, g
from blockchain import Blockchain
from transaction import Transaction
from block import Block
import json
from node import Node
import logging

#we have to define node here because we cant import it from the main program: there we import bp and it would create a circular import
node = Node()

bp = Blueprint('endpoints', __name__)
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
#node sends to bootstrap its info and he adds it to the ring and sends it the next id
@bp.route('/register_node', methods=['POST'])
def register_node():
    global node
    data = request.get_json()
    node_ipaddr = data['ip_address']
    node_port = data['port']
    node_pubkey = data['pubkey']
    node_id = 'id' + str(len(node.node_ring))
    node.add_to_ring(node_ipaddr, node_pubkey, node_port, node_id)
    #logging.info(node.wallet.coins)
    return jsonify({"message": "Node registered successfully", "id": len(node.node_ring)-1}), 200

#called when bootstrap broadcasts the nodering
@bp.route('/update_node_ring', methods=['POST'])
def update_node_ring():
    global node
    data = request.get_json()
    node_ring = data['node_ring']
    node.node_ring = node_ring
    #logging.info(node.node_ring)  
    return jsonify({"message": "Node ring updated successfully"}), 200

def deserialize(block_list):
    result = []

    for ser_block in block_list:
        #ser_block = json.loads(ser_block)
        index = ser_block['index']
        timestamp = ser_block['timestamp']
        validator = ser_block['validator']
        previous_hash = ser_block['previous_hash']
        current_hash = ser_block['current_hash']

        transactions = []
        for transaction_dict in ser_block['transactions']:
            sender = transaction_dict['sender_address']
            receiver = transaction_dict["receiver_address"]
            type = transaction_dict["type"]
            n = transaction_dict['nonce']
            am = transaction_dict['amount']
            msg = transaction_dict['message']
            id = transaction_dict['transaction_id']
            trans = Transaction(sender_address = sender, receiver_address=receiver, type_of_transaction=type, nonce = n, amount=am, message=msg, id=id)
            transactions.append(trans)
       
        block = Block(index=index, transactions=transactions, validator=validator, previous_hash=previous_hash, t=timestamp, hash=current_hash)
        result.append(block)

    return result

def deserialize_block(ser_block):
    index = ser_block['index']
    timestamp = ser_block['timestamp']
    validator = ser_block['validator']
    previous_hash = ser_block['previous_hash']
    current_hash = ser_block['current_hash']

    transactions = []
    for transaction_dict in ser_block['transactions']:
        sender = transaction_dict['sender_address']
        receiver = transaction_dict["receiver_address"]
        type = transaction_dict["type"]
        n = transaction_dict['nonce']
        am = transaction_dict['amount']
        msg = transaction_dict['message']
        id = transaction_dict['transaction_id']
        trans = Transaction(sender_address = sender, receiver_address=receiver, type_of_transaction=type, nonce = n, amount=am, message=msg, id=id)
        transactions.append(trans)
       
    block = Block(index=index, transactions=transactions, validator=validator, previous_hash=previous_hash, t=timestamp, hash=current_hash)
    return block

def deserialize_transactions(transactions_json):
    """
    Returns:
        list: A list of Transaction objects.
    """
    transactions_list = json.loads(transactions_json)
    deserialized_transactions = []

    # Loop through each transaction dictionary in the list
    for transaction_dict in transactions_list:
        # Extract data for each Transaction object
        sender = transaction_dict['sender_address']
        receiver = transaction_dict['receiver_address']
        type_of_transaction = transaction_dict['type']
        nonce = transaction_dict.get('nonce') 
        amount = transaction_dict['amount']
        message = transaction_dict.get('message') 
        transaction_id = transaction_dict.get('transaction_id')  

        trans = Transaction(sender_address=sender, receiver_address=receiver, type_of_transaction=type_of_transaction, 
                            nonce=nonce, amount=amount, message=message, id=transaction_id)
        deserialized_transactions.append(trans)

    return deserialized_transactions

#called when bootstrap broadcasts the blockchain
@bp.route('/update_blockchain', methods=['POST'])
def update_blockchain():
    global node
    data = request.get_json()
    data = json.loads(data)
    #logging.info(data)
    #logging.info('-----------------------------------------------------------')
    block_list = deserialize(data['blockchain'])

    blockchain = Blockchain(block_list)
    if not node.validate_chain(blockchain):
        return jsonify({"message": "Chain validation failed."}), 400

    node.blockchain = blockchain
    #logging.info(node.blockchain)  
    #for debugging
    #logging.info("------------------------ update -------------------")
    return jsonify({"message": "Blockchain updated successfully"}), 200

@bp.route('/add_block', methods=['POST'])
def add_block():
    global node
    data = request.get_json()
    data = json.loads(data)
    #logging.info(data)
    #logging.info('-----------------------------------------------------------')
    block = deserialize_block(data['block'])
    prev_block = node.blockchain.blocks[-1]

    if not node.validate_block(block, prev_block):
        return jsonify({"message": "Block validation failed."}), 400

    node.blockchain.add_block_to_chain(block)

    return jsonify({"message": "Block added successfully"}), 200

#invoked when login phase is complete, in order to start making transactions
@bp.route('/start_transactions', methods=['POST'])
def start_transactions():
    #logging.info("================ Start_Transactions was called =========================")
    global node
    node.start_transactions = True
    node.test()
    return jsonify({"message": "Transactions starting."}), 200
    

#invoked when a transaction is broadcasted, in order to validate it
@bp.route('/receive_transaction', methods=['POST'])
def receive_transaction():
    global node
    transaction_json = request.get_json()
    if node.validate_transaction(transaction_json):
        return jsonify({"message": "Transaction received and validated."}), 200
    else:
        return jsonify({"message": "Transaction validation failed."}), 400

@bp.route('/receive_boot_transactions', methods=['POST'])
def receive_boot_transactions():
    global node  
    transactions_json = request.json.get('transactions')
    node.transactions = deserialize_transactions(transactions_json)
    for trans in node.transactions:
        node.seen.add(trans.transaction_id)
    return jsonify({"message": "Boot transactions received successfully."}), 200