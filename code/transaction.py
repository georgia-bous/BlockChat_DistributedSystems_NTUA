import hashlib
from typing import Optional
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Maybe transaction adresses should not be string, but actualy Key objects. From key objects we can extract the string easily.
class Transaction:
    def __init__(self, sender_address: str, receiver_address: str, type_of_transaction: str, nonce: int = None, amount: float = 0, message: str= None):
        self.sender_address = sender_address
        self.receiver_address = receiver_address
        self.type_of_transaction = type_of_transaction
        self.amount = amount
        self.message = message
        self.nonce = nonce  #we dont need it
        self.transaction_id = self.calculate_transaction_id()

    def calculate_transaction_id(self):
        """
        Calculates the hash of the transaction using SHA-256 algorithm.
        """
        if self.message is None:
            tx_content = f"{self.sender_address}{self.receiver_address}{self.type_of_transaction}{self.amount}{self.nonce}".encode()
        else:
            tx_content = f"{self.sender_address}{self.receiver_address}{self.type_of_transaction}{self.message}{self.nonce}".encode()
        return hashlib.sha256(tx_content).hexdigest()
    
    
    def as_serialised_dict(self):
        sender_address_ser = self.sender_address.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sender_address_ser = sender_address_ser.decode('utf-8')

        receiver_address_ser = self.receiver_address.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        receiver_address_ser = receiver_address_ser.decode('utf-8')

        result = {
            'sender_address': sender_address_ser,
            'receiver_address': receiver_address_ser,
            'type': self.type_of_transaction,
            'amount': self.amount,
            'message': self.message,
            'nonce': self.nonce,
            'transaction_id': self.transaction_id  # Assuming this is already a string
        }
        return result
    
    def sign_transaction(self, private_key):
        hash = self.transaction_id.encode() #transaction_id is the hash of the transaction, do i need encode? isnt it already in bytes?
        #private_key = self.wallet.private_key
        signature = private_key.sign(
            hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return signature
    
    def transaction_amount(self, is_boot_transaction=False):
        if self.type_of_transaction == 'coins':
            if is_boot_transaction:
                total = self.amount
            else:
                total = self.amount + 0.03 * self.amount #+3% charge
            return total
        elif self.type_of_transaction == 'message':
            return len(self.message)
        else:
            print('Invalid type of transaction.')
            return 0