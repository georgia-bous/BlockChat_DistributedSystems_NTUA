from wallet import Wallet
from transaction import Transaction
from typing import List, Any , Optional
from flask import jsonify
import random
import re
import argparse
import sys
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
import logging
'''
#keep them stable or find a way to take them from main, cannot import
n=3
stake=10
capacity=5
'''
#we have to either add block attribute to the node or define create_transaction in main
class Node:
    def __init__(self, id:str=None, capacity:int= None, stake= None, nnodes:int= None, block=None, node_ring={}, ring_balances:List[Any]=[], ring_stakes:List[Any]=[]):
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
        self.node_ring = {}    
        self.block = block     #current block
        self.ring_balances = ring_balances
        self.ring_stakes = ring_stakes  
        self.nonce = 0      # the number of transactions SENT
        self.transactions = []  #keep track the transactions that are gonna be on the next block
        self.blockchain = Blockchain()
        self.login_complete = False
        self.start_transactions = False
        self.bootstrap_pk = None
        self.seen = set()

        logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

    #sender and receiver address are in byte format for hash
    def create_transaction(self, sender_address, receiver_address, type_of_transaction, amount= None, message= None):
        transaction = Transaction(sender_address, receiver_address, type_of_transaction, self.nonce, amount, message)
        if sender_address == 0:  #the first transaction, create transaction is never called
            #self.transactions.append(transaction)
            self.nonce+= 1
            self.wallet.coins += 1000*self.nnodes  #do it in a function??

            # Create the genesis block to contain the initial transaction. Add that block to the blockchain.
            #genesis_block = Block(index=0, transactions=[transaction], validator=0, previous_hash=1)
            #self.blockchain.add_block_to_chain(genesis_block)

            return transaction
        
        signature = transaction.sign_transaction(self.wallet.private_key) #byte format
        self.broadcast_transaction(transaction, signature)
        ####
        if len(self.transactions) == self.capacity:
            #execute the transactions in the list for the receivers side
            self.mint_block()
            self.transactions = []
        else:                    
            #logging.info('Not minting because transaction length is: ', len(self.transactions))
            pass

        return transaction


    def send_transaction_to_node(self, node, transaction_json):
        try:
            node_url = f'http://{node["ip_addr"]}:{node["port"]}/receive_transaction'
            response = requests.post(node_url, json=transaction_json, headers={'Content-Type': 'application/json'})

            if response.status_code == 200:
                #print(f"Transaction successfully sent to {node['ip_addr']}:{node['port']}")
                return True #the transaction was validated
            else:
                #logging.info(f"Failed to send transaction to {node['ip_addr']}:{node['port']}. Response code: {response.status_code}")
                return False #the transaction was not validated
        
        except requests.exceptions.RequestException as e:
            #logging.info(f"Error sending transaction to {node['ip_addr']}:{node['port']}: {e}")
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
        for _,node in self.node_ring.items():
            if node['pubkey'] != self.wallet.pubkey_serialised():
                #logging.info(node['port'])
                t = threading.Thread(target=thread_target, args=(node, transaction_json,))
                threads.append(t)
                t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        if all(validation_statuses):
            #logging.info("All nodes validated the transaction.")
            self.transactions.append(transaction)
            self.nonce+= 1
            #self.wallet.coins -= transaction.transaction_amount(is_boot_transaction = True)
            node_dict = self.node_ring[self.wallet.pubkey_serialised()]
            if self.start_transactions: 
                node_dict['balance'] -= transaction.transaction_amount(is_boot_transaction = not self.start_transactions)

            #logging.info([node['balance'] for k,node in self.node_ring.items()])

        else:
            #logging.info("One or more nodes failed to validate the transaction.")
            pass

    
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
            #logging.info("Signature verification successful.")
            return True
        except Exception as e:
            #logging.info(f"Signature verification failed: {e}")
            return False
        

    def validate_transaction(self, transaction_json):
        transaction_dict = json.loads(transaction_json)
        
        ver_sign = self.verify_signature(transaction_dict['transaction_id'], transaction_dict['sender_address'], transaction_dict['signature'])
        if ver_sign == False :
            return False
        
        # If login is still going, you dont have the ring data (keys, balances, stakes) and there is nothing
        # to really check. Just return, and don't keep the transaction.
        if not self.login_complete:
            return True
        
        if transaction_dict['type'] == 'coins':
            coins_needed = transaction_dict['amount'] + 0.03 * transaction_dict['amount']  #+3% charge
        elif transaction_dict['type'] == 'message':
            coins_needed = len(transaction_dict['message'])
        # for stake
        elif transaction_dict['type'] == 'stake':
            print("Validated Stake Transaction")
            coins_needed = transaction_dict['amount']
            #return True
        else:
            #logging.info('Wrong type of transaction.')
            return False
        # if stake return true
        
        sender_dict = self.node_ring[transaction_dict['sender_address']]
        balance = sender_dict['balance']
        stake = sender_dict['stake']
        if coins_needed > balance + stake:  
            #logging.info('Sender does not have enough coins.')
            return False
        else:
            #logging.info('Sender okay to send.')
            
            # If login is done, we keep the transaction. 
            # Afterwards, we check if we need to mint a block.
            if self.login_complete:    
                sender = transaction_dict['sender_address']
                receiver = transaction_dict["receiver_address"]
                type = transaction_dict["type"]
                n = transaction_dict['nonce']
                am = transaction_dict['amount']
                msg = transaction_dict['message']
                id = transaction_dict['transaction_id']
                trans = Transaction(sender_address = sender, receiver_address=receiver, type_of_transaction=type, nonce = n, amount=am, message=msg, id=id)

                # Update the sender balance.
                if type != 'stake':
                    node_dict = self.node_ring[sender] 
                    node_dict['balance'] -= trans.transaction_amount()

                #logging.info('balances after trans', [node['balance'] for k,node in self.node_ring.items()])

                # Add the recieved transaction, only if it has not been seen in a previous block!
                if id not in self.seen:    
                    self.transactions.append(trans)

                    if len(self.transactions) == self.capacity:
                        self.mint_block()
                        self.transactions = []
                    else:
                        pass
                        #logging.info('Not minting because transaction length is: ', len(self.transactions))

            return True


    def validate_block(self, block:Block, prev_block:Block):
        # Check the validator. If login is not complete, it should always be the bootstrap.
        if not self.login_complete:
            if block.validator != self.bootstrap_pk:
                print('validation fails case 1')
                return False
        
        # If login is over, we run the rullete to find the validator
        if self.login_complete:
            if block.validator != self.rulette(prev_hash=prev_block.current_hash):
                print('validation fails case 2')
                return False

        if block.previous_hash != prev_block.current_hash:
            print('validation fails case 3')
            return False
        
        # Run through the transactions of the block and update the recipient balances.
        if self.login_complete:
            self.update_recipient_balances(block)

        print('balances after blcok validate ',[node['balance'] for k,node in self.node_ring.items()])            
        return True
    
    def update_recipient_balances(self,block):
        #logging.info('Validating block from minter', block.validator)
        for trans in block.transactions:
            # delete from list of pending transactions, if its still there.

            #previous code
            #for i in range(len(self.transactions)):
                #if self.transactions[i].transaction_id == trans.transaction_id:
                    #del self.transactions[i]
            i = 0  
            while i < len(self.transactions):
                if self.transactions[i].transaction_id == trans.transaction_id:
                    del self.transactions[i]
                    continue  
                i += 1  

            if trans.transaction_id not in self.seen:
                if trans.type_of_transaction == 'coins':
                    recipient = trans.as_serialised_dict()['receiver_address']

                    amount = trans.amount

                    # Update recipient balance
                    self.node_ring[recipient]['balance'] += amount

                    # Give 3% to the block validator
                    validator = block.validator
                    self.node_ring[validator]['balance'] += amount*0.03
                #for stake
                elif trans.type_of_transaction == 'stake':
                    sender = trans.as_serialised_dict()['sender_address']
                    self.node_ring[sender]['stake'] = amount
                    print("Stake Updated")

                self.seen.add(trans.transaction_id)

    def validate_chain(self, chain:Blockchain):
        self.bootstrap_pk = chain.blocks[0].transactions[0].receiver_address

        # Validate all except the first as it is the genesis block.
        for i in range(1, len(chain.blocks)):
            block = chain.blocks[i]
            prev_block = chain.blocks[i-1]
            if not self.validate_block(block, prev_block):
                return False
            
        self.login_complete = True    
        return True
            


    #bootsrap calls it
    #node ring is going to be a list of json objects, each one containing the attributes of a node
    def add_to_ring(self, ip_addr: str, pubkey_str:str, port: int, node_id:str): 
        node_info = {
            "ip_addr": ip_addr,
            "pubkey": pubkey_str,
            "port": port,
            "stake": 10,
            "balance": 1000,
            "id": node_id
        }
            
        # add node to ring
        self.node_ring[pubkey_str] = node_info
        
        #convert to byte format
        pubkey = serialization.load_pem_public_key(
            pubkey_str.encode(),  # Convert string to bytes
            backend=default_backend()
        )

        # send coins to the new node (if its not bootstrap)
        if len(self.node_ring.items())>1:
            self.create_transaction(self.wallet.public_key, pubkey, 'coins', 1000)

        #when all nodes are added, broadcast the node ring
        #for debugginh
        #logging.info("Node ring items: "+str(len(self.node_ring.items())))
        #logging.info("NNodes: " + str(self.nnodes))
        if len(self.node_ring.items()) == self.nnodes:
            self.broadcast_node_ring()

            #add code to broadcast the blockchain
            #logging.info(self.blockchain.as_serialised_dict())
            self.broadcast_blockchain()
            
            # Let the nodes know that they can start the transactions, by setting a boolean flag.
            #for debuggin
            #logging.info("---------------- Nodes Reached add_to_ring --------------------------")
            self.initiate_transactions() 

    def initiate_transactions(self):
        # for debugging
        #logging.info("====================== Initiate was called =====================")
        self.login_complete = True
        self.start_transactions = True
        #for debug
        #print("Len of ring items: " + str(len(self.node_ring.items())))
        #print(self.node_ring.items())
        for k,node in self.node_ring.items():
            #for debug
            #print("K: "+ str(k))
            #print(node)
            #logging.info("============================= Inside the loop in initiate_transactions =======================")
            if node['pubkey'] != self.wallet.pubkey_serialised():
                #for debug
                #logging.info("================== Inside the if in initiate transactions ================")
                url = f"http://{node['ip_addr']}:{node['port']}/start_transactions"
                try:
                    response = requests.post(url)
                    #logging.info("Response status code: " + str(response.status_code))
                    if response.status_code == 200:
                        #logging.info(f"Transactions start successfully on {node['ip_addr']}")
                        pass
                    else:
                        pass
                       #logging.info(f"Failed to start transactions on {node['ip_addr']}")
                    #print(f"Node responded: {response.json()}")
                except Exception as e:
                    logging.info(f"Error starting transactions on {node['ip_addr']}: {e}")
                    pass
        #self.create_cli()
        self.test()

    # Send a test transaction after we initiate them.
    def test(self):
        #logging.info('Login is', self.login_complete)
        #logging.info('Transactions are', self.start_transactions)

        # Hardcoded transactions for debugging
        '''rec = list(self.node_ring.values())[1]['pubkey']
        if rec == self.wallet.pubkey_serialised():
            rec = list(self.node_ring.values())[0]['pubkey']
        self.create_transaction(self.wallet.public_key, rec, 'message',message='HELLO')

        rec = list(self.node_ring.values())[2]['pubkey']
        if rec == self.wallet.pubkey_serialised():
            rec = list(self.node_ring.values())[1]['pubkey']
        self.create_transaction(self.wallet.public_key, rec, 'message',message='HELLO')'''

        # Real transactions from input files.
        id = self.node_ring[self.wallet.pubkey_serialised()]['id']
        number_part = id[2:]  # Get input file name
        # TODO change this directory if its working on linux
        input_file = 'code/input/trans' + number_part + '.txt'
        #self.parse_file(input_file)
        #logging.info("================================================================")
        #self.create_cli()
    # Helper that parses the input file, gets the messages from each line, and sends them as transactions.
    def parse_file(self, input_file):
        with open(input_file, 'r') as file:
            lines = file.readlines()
        
        # Regular expression pattern to match 'id' followed by a number and the message
        pattern = r'id(\d+)\s(.+)'
        id_str = None
        message_str = None

        for line in lines:
            # Use regular expression to find matches
            match = re.match(pattern, line)
            if match:
                # Extract id and message from the match
                id_str = 'id'+match.group(1)
                message_str = match.group(2)
            
            recipient_pk = None
            # Retrieve the recipient public key, by its id
            for pk, node_dict in self.node_ring.items():
                if node_dict['id'] == id_str:
                    recipient_pk = pk
                    break
            
            # TODO change this if we are running with more nodes.
            if id_str <= 'id2':
                self.create_transaction(self.wallet.public_key, recipient_pk, 'message',message=message_str)


    #bootstrap calls it
    def broadcast_node_ring(self):
        for _,node in self.node_ring.items():
            if node['pubkey'] != self.wallet.pubkey_serialised():
                url = f"http://{node['ip_addr']}:{node['port']}/update_node_ring"
                try:
                    response = requests.post(url, json={"node_ring": self.node_ring})
                    '''if response.status_code == 200:
                        print(f"Node ring broadcasted successfully to {node['ip_addr']}")
                    else:
                        print(f"Failed to broadcast to {node['ip_addr']}")'''
                    #print(f"Node responded: {response.json()}")
                except Exception as e:
                    logging.info(f"Error broadcasting to {node['ip_addr']}: {e}")

    #bootstrap calls it
    def broadcast_blockchain(self):
        self.login_complete = True
        blockchain_data = self.blockchain.as_serialised_dict()

        blockchain_json = json.dumps(blockchain_data)
        for k,node in self.node_ring.items():
            if node['pubkey'] != self.wallet.pubkey_serialised():
                # for debuggin
                #logging.info("==================== Inside the broadcast_blockchain ================")
                url = f"http://{node['ip_addr']}:{node['port']}/update_blockchain"
                try:
                    response = requests.post(url, json=blockchain_json)
                    if response.status_code == 200:
                        #logging.info(f"Blockchain broadcasted successfully to {node['ip_addr']}")
                        pass
                    else:
                        #logging.info(f"Failed to broadcast blockchain to {node['ip_addr']}")
                        pass
                    #logging.info(f"Node responded: {response.json()}")
                except Exception as e:
                    pass
                    #logging.info(f"Error broadcasting blockchain to {node['ip_addr']}: {e}")

    # Helper for mint_block random sampling
    # Runs the rulette that picks the validator, based on the stakes.
    # Returns the validator public key
    def rulette(self, prev_hash):
        # Sort the node_ring dictionary on the public keys, to ensure that all nodes see the same order.
        # The result ring_list is a list of pairs.
        # First element of the pair is the node public key (serialised).
        # Second element of the pair is the node dictionary with the node info (balance,stake,ip...)
        ring_list = sorted(list(self.node_ring.items()))
        hash = prev_hash
        seed = int(hash, 16) % (10 ** 16)
        random.seed(seed)
        random_number = random.random()

        # Perform the random sampling, based on the stakes.
        sum=0
        for _,node_dict in ring_list:
            sum += node_dict['stake']
            
        x=0
        list1=[]
        for _,node_dict in ring_list:
            list1.append(x+node_dict['stake']/sum)
            x=x+node_dict['stake']/sum
        #list1 contains cumulative sum
        for i in range (0,len(list1)):
            if random_number<list1[i]:
                return ring_list[i][0] # public key of the validator.

    def mint_block(self):
        #PoS -> validator will create block with transactions and broadcast it -> nodes will validate it and receivers will update their wallets
        
        # If the node login phase is not yet completed, then the validator will always be the bootstrap node.
        #print("test mint")
        if not self.login_complete:
            #print("mint not complete")
            i=len(self.blockchain.blocks)
            t=list(self.transactions)
            val=self.wallet.pubkey_serialised()
            hash = self.blockchain.blocks[-1].current_hash
            block = Block(index=i, transactions=t, validator=val, previous_hash=hash)

            self.blockchain.add_block_to_chain(block)
        
            # Empty the transactions
            self.transactions = []
        else: # Login phase is over, so we mint by drawing a random generator.
            #print("mint complete")
            validator_pk = self.rulette(prev_hash=self.blockchain.blocks[-1].current_hash)
            # If validator is myself, I create a block and broadcast it, identical to above. 
            # Else nothing happens.            
            if self.wallet.pubkey_serialised() == validator_pk:
                #print("validator")
                #logging.info('I AM VALIDATING BLOCK')
                i=len(self.blockchain.blocks)
                t=list(self.transactions)
                val=self.wallet.pubkey_serialised()
                hash = self.blockchain.blocks[-1].current_hash
                block = Block(index=i, transactions=t, validator=val, previous_hash=hash)

                self.transactions = []
                self.blockchain.add_block_to_chain(block)

                if self.validate_block(block, prev_block=self.blockchain.blocks[-2]):
                    print("Validated")
                    self.broadcast_block(block)
                else:
                    print("Error while validating")
           

        return

    def broadcast_block(self, block):
        block_data = {'block': block.as_serialised_dict()}

        block_json = json.dumps(block_data)
        for k,node in self.node_ring.items():
            if node['pubkey'] != self.wallet.pubkey_serialised():
                url = f"http://{node['ip_addr']}:{node['port']}/add_block"
                try:
                    response = requests.post(url, json=block_json)
                    if response.status_code == 200:
                        print(f"Block broadcasted successfully to {node['ip_addr']}")
                    else:
                        print(f"Failed to broadcast block to {node['ip_addr']}")
                        print(f"Node responded: {response.json()}")
                except Exception as e:
                    print(f"Error broadcasting block to {node['ip_addr']}: {e}")
                


    def print_help(self):
        print("-----------------------------------------------------------------------------------------------------------\n")
        print("t <recipient_address> <coins> : Create a new transaction. Send to <recipient_address> a number of <coins>.\n")
        print("t <recipient_address> <message> : Create a new transaction. Send to <recipient_address> a <message>.\n")
        print("stake <amount> : Set the node stake. Set an <amount> of coins for the node's staking.\n")
        print("view : View the transactions of the last validated block in the blockchain as well as its validator's id.\n")
        print("balance : See the balance of your wallet.\n")
        print("-----------------------------------------------------------------------------------------------------------\n")

    #for stake
    def set_stake(self,stake_amount):
        sender = self.wallet.public_key
        receiver = 0
        print("New stake: " + str(stake_amount))
        self.create_transaction(sender_address=sender, receiver_address=receiver, type_of_transaction='stake',amount=stake_amount,message=None)

    def view_block(self):
        print("\n")
        number_of_transactions = 1
        for trans in self.blockchain.blocks[-1].block_transactions():
            print("------------------------------ Transaction " + str(number_of_transactions)+ " ------------------------------\n")
            trans.view_transaction()
            number_of_transactions = number_of_transactions + 1
            print("\n")
        print("------------------------------------------------------------------------\n")
        print("Block's Validator: " + str(self.blockchain.blocks[-1].block_validator()))


    def show_balance(self):
        print("Balance: " + str(self.node_ring[self.wallet.pubkey_serialised()]['balance']))

    def cli_create_transaction(self, recipient, mess):
        print("Recipient: " + str(recipient))
        print("Message: " + str(mess))
        try:
            amount = float(mess)
            if amount.is_integer():
                amount = int(amount)
                cli_type_of_transaction = 'coins'
                cli_amount = amount
                cli_message = None
        except ValueError:
            cli_type_of_transaction = 'message'
            cli_amount = None
            cli_message = mess

        cli_recipient_address = None
        recipient_id = 'id'+ recipient
        for pk, node_dict in self.node_ring.items():
            if node_dict['id'] == recipient_id:
                cli_recipient_address = pk
                break
        cli_sender_address = self.wallet.public_key
        self.create_transaction(sender_address=cli_sender_address, receiver_address=cli_recipient_address, type_of_transaction=cli_type_of_transaction,amount=cli_amount,message=cli_message)


    def create_cli(self):
        parser = argparse.ArgumentParser(description="Blockchain CLI", add_help=False)
        subparsers = parser.add_subparsers()

        parser_t = subparsers.add_parser('t', help='New transaction or message')
        parser_t.add_argument('recipient_address', type=str, help='Recipient address')
        parser_t.add_argument('message', type=str, help='Message')
        parser_t.set_defaults(func=self.cli_create_transaction)

        parser_stake = subparsers.add_parser('stake', help='Set the node stake')
        parser_stake.add_argument('amount', type=float, help='Stake amount')
        parser_stake.set_defaults(func=self.set_stake)

        parser_view = subparsers.add_parser('view', help='View last block')
        parser_view.set_defaults(func=self.view_block)

        parser_balance = subparsers.add_parser('balance', help='Show balance')
        parser_balance.set_defaults(func=self.show_balance)

        parser_help = subparsers.add_parser('help', help='Print help')
        parser_help.set_defaults(func=self.print_help)

        while True:
            try:
             input_string = input("Blockchain CLI: ")
            except EOFError:
                break  # Exit on Ctrl-D

            if input_string.lower() in ["exit", "quit"]:
                print("Exiting...")
                break  # Exit loop

    # Split the input into arguments
            argv = input_string.split()
            #print(argv)

    # Check if the input is not empty and prepend a dummy script name
            if argv:
                #argv = ['main.py'] + argv
                argv=argv
            else:
                print("No command entered. Please enter a command.")
                continue

    # Parse the arguments
            try:
                args = parser.parse_args(argv)  # Parse arguments without a dummy script name
                if hasattr(args, 'func'):
                    arg_values = list(vars(args).values())[:-1]  # Exclude the last argument
                    #print(*arg_values)
                    args.func(*arg_values) 
                else:
                    parser.print_help()
            except SystemExit:
                continue
