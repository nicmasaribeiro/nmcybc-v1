import binascii
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
#from Crypto.Hash import SHA25
from transaction import Transaction
class Wallet:
    def __init__(self):
        random_gen = Crypto.Random.new().read
        self.private_key = RSA.generate(1024, random_gen)
        self.public_key = self.private_key.publickey()

    def export_keys(self):
        private_key = binascii.hexlify(self.private_key.export_key(format='DER')).decode('ascii')
        public_key = binascii.hexlify(self.public_key.export_key(format='DER')).decode('ascii')
        return private_key, public_key

    def create_transaction(self, recipient: str, amount: float) -> Transaction:
        private_key, public_key = self.export_keys()
        transaction = Transaction(sender=public_key, recipient=recipient, amount=amount)
        transaction.sign_transaction(private_key)
        return transaction
    