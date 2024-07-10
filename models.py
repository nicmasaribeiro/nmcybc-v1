#from flask import Flask, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import time
import enum
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa 
from classes import PrivateWallet, Balance
import socket
from sqlalchemy import create_engine
from sqlalchemy.orm import *
from flask import Flask, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import create_engine, ARRAY
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import enum
import os
import sys
from sqlalchemy.ext.mutable import MutableList

UPLOAD_FOLDER = './static'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Initialize Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blockchain.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24).hex()

# Initialize SQLAlchemy
db = SQLAlchemy(app)
# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)
login_manager.login_view = 'login'

engine = create_engine('sqlite:///commands.db')
Session = sessionmaker(bind=engine)()

class Wallet(db.Model):
    __tablename__ = 'wallets'
    
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String, unique=True, nullable=False)
    balance = db.Column(db.Float, default=0)
    password = db.Column(db.String(1024))
    coins = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    token = db.Column(db.String(3072))

    def set_transaction(sender_wallet, recv_wallet, value):
        sender = sender_wallet
        recv = recv_wallet
        money = value
        sender_bal = sender_wallet.balance
        recv_bal = recv_wallet.balance
        if sender_bal > float(value):
            sender_new_bal = float(sender_bal) - float(value)
            recv_new_bal = float(recv_bal) + float(value)
            sender_wallet.balance = sender_new_bal
            recv_wallet.balance = recv_new_bal
            db.session.commit()

    def add_money(self,value):
        self.balance+=float(value)
        db.session.commit()
    
    def add_coins(self,value):
        self.coins+=float(value)
        db.session.commit()
        
    def sell_coins(value):
        Wallet.balance += value
        Wallet.coins -= value
        db.session.commit()
    
    def buy_coins(value):
        Wallet.balance -= value
        Wallet.coins += value
        db.session.commit()
        
class BettingHouse(db.Model):
    __tablename__ = 'house'

    id = db.Column(db.Integer,unique=True, primary_key=True)
    balance = db.Column(db.Float, default=0)
    coins = db.Column(db.Float, default=1000000000)
    
    def cash_fee(self,value):
        self.balance +=float(value)
        db.session.commit()
    
    def coin_fee(self,value):
        self.balance += float(value)
        db.session.commit()
    
class Users(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer,unique=True, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    payment_id = db.Column(db.String(1024))
    private_wallet = PrivateWallet()
    personal_token = db.Column(db.String(3072))
    private_token = db.Column(db.String(3072))
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallets.id'), nullable=True)
    wallet = db.relationship('Wallet', backref='user', uselist=False)

class TransactionType(enum.Enum):
    send = "send"
    receive = "receive"
    internal_wallet = "internal_wallet"
    intra = "intra"
    investment = "investment"
    liquidation = 'liquidation'
    
class TransactionDatabase(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    txid = db.Column(db.String, nullable=False)
    username = db.Column(db.String)
    from_address = db.Column(db.String, db.ForeignKey('wallets.address'))
    to_address = db.Column(db.String, db.ForeignKey('wallets.address'))
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.Enum(TransactionType), nullable=False)
    signature = db.Column(db.String(1024))
    
    from_wallet = db.relationship('Wallet', foreign_keys=[from_address])
    to_wallet = db.relationship('Wallet', foreign_keys=[to_address])
    
class Peer(db.Model):
    __tablename__ = 'peers'
    
    id = db.Column(db.Integer,unique=True ,primary_key=True)
    user_address = db.Column(db.String, unique=True, nullable=False)#, unique=True, nullable=False
    pk = db.Column(db.String(120))
    miner_wallet =  db.Column(db.Integer, default=0)
    cash = db.Column(db.Integer, default=0)
    keyPair = db.Column(db.LargeBinary(1024))
    email = db.Column(db.String(120))
    password = db.Column(db.String(120), nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    def add_coins(self,value):
        self.miner_wallet += value
        db.session.commit()
        
    def sell_coins(self,value):
        self.miner_wallet -= value
        self.cash += value
        db.session.commit()
        
class Block(db.Model):
    __tablename__ = 'blocks'
    
    id = db.Column(db.Integer,unique=True,primary_key=True)
    index = db.Column(db.Integer)
    previous_hash = db.Column(db.String, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    hash = db.Column(db.String)
    transactions = db.Column(db.LargeBinary(1024))

    
class BlockchainPending(db.Model):
    __tablename__ = 'blocks_pending'
    
    id = db.Column(db.Integer,unique=True, primary_key=True)
    index = db.Column(db.Integer)
    previous_hash = db.Column(db.String)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    data = db.Column(db.PickleType())
    hash = db.Column(db.String)

class PrivateBlock:
	def __init__(self, index, previous_hash, timestamp, transactions, hash=None):
		self.index = index
		self.previous_hash = previous_hash
		self.timestamp = timestamp
		self.transactions = transactions
		self.hash = hash or self.calculate_hash()
		
	def calculate_hash(self):
		return hashlib.sha256(str(self.index).encode())    

class MiningStatus(enum.Enum):
    pending = "pending"
    completed = "completed"
    failed = "failed"

class OptionInvestment(db.Model):
    __tablename__ = 'option_token'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(1024),unique=False)
    user_address = db.Column(db.String(1024), unique=False)#, unique=True, nullable=False
    transaction_receipt = db.Column(db.String)
    asset_name = db.Column(db.String,default=0.0)
    quantity = db.Column(db.Float())
    strike = db.Column(db.Float(), default=0)
    maturity = db.Column(db.Float(), default=0.0)
    risk_free = db.Column(db.Float())
    vol = db.Column(db.Float())
    change_value = db.Column(db.Float(), default=0.0)
    starting_price = db.Column(db.Float(), default=0.0)
    market_price = db.Column(db.Float,default=0.0)
    
class AtomizedInvestment(db.Model):
    __tablename__ = 'atom_token'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(1024),unique=False)
    user_address = db.Column(db.String(1024), unique=False)#, unique=True, nullable=False
    transaction_receipt = db.Column(db.String)
    quantity = db.Column(db.Integer,default=0.0)
    coins_value = db.Column(db.Integer, default=0)
    
class AssetToken(db.Model):
    __tablename__ = 'asset_token'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(1024),unique=False)
    token_address = db.Column(db.String(1024), unique=False)
    user_address = db.Column(db.String(1024), unique=False)#, unique=True, nullable=False
    transaction_receipt = db.Column(db.String)
    quantity = db.Column(db.Integer,default=0.0)
    cash = db.Column(db.Integer, default=0)
    coins = db.Column(db.Integer, default=0)

class CoinDB(db.Model):
    __tablename__ = 'coins'
    
    id = db.Column(db.Integer,unique=True, primary_key=True)
    market_cap = db.Column(db.Integer,default=0)
    staked_coins = db.Column(db.Integer,default=0)
    new_coins = db.Column(db.Integer,default=0)
    dollar_value = db.Column(db.Integer,default=0.01)
    total_coins = db.Column(db.Integer,default=1_000_000_000_000)
    
    def gas(self,blockchain,gas):
        if 10 > gas > 1:
            dif = 10 - gas
            chain = blockchain.chain
            for i in chain:
                nonce, hash_result, time_taken = blockchain.proof_of_work(i, difficulty=5)
                self.new_coin(float(time_taken))
            return "Success"
        else:
            return "Wrong Gas"
        
    def new_coin(self,value):
        self.new_coins += value
        db.session.commit()
        
    def proccess_coins(self,blockchain):
        new=[]
        for i in blockchain.stake:
            nonce, hash_result, time_taken = blockchain.proof_of_work(i,5)
            new.append(float(time_taken))
        self.staked_coins = sum(new)
        db.session.commit()
    
    def convert_mc(self):
        new=[]
        for coin in self.staked_coins:
            new.append(coin)
        self.market_cap = sum(new)
        db.session.commit()
        
class InvestmentDatabase(db.Model):
    __tablename__ = 'investments'
    
    id = db.Column(db.Integer, unique=True ,primary_key=True)
    owner =  db.Column(db.String(1024))
    investment_name = db.Column(db.String(1024))
    password = db.Column(db.String(1024))
    quantity = db.Column(db.Float(),default=0.0)
    market_cap = db.Column(db.Float(), default=0.0)
    change_value = db.Column(db.Float(), default=0.0)
    starting_price = db.Column(db.Float(), default=0.0)
    market_price = db.Column(db.Float,default=0.0)
    coins_value = db.Column(db.Float(), default=0.0)
    investors = db.Column(db.Integer)
    receipt = db.Column(db.String(1024),unique=True)
    tokenized_price = db.Column(db.Float,default=0.0) # tokenized_value
    ls = MutableList(default=[])

    def update_token_value(self):
        self.tokenized_price = self.market_cap/self.coins_value
        db.session.commit()
    
    def add_market_cap(self,value):#name
        self.market_cap+=float(value)
        db.session.commit()
    
    def add_stake(self,value):#name
        self.coins_value+=float(value)
        db.session.commit()
    
    def add_investor(self):
        self.investors += 1
        db.session.commit()
   
    def append_investor_token(self,name,address,receipt,amount,currency):
        self.ls += [{'name':name,'address':address,'receipt':receipt,'amount':amount,'currency':currency}]
        # db.session.add(self.ls)
        db.session.commit()

class TrackInvestors(db.Model):
    __tablename__ = 'tracking'
    
    id = db.Column(db.Integer, unique=True ,primary_key=True)
    receipt = db.Column(db.String(1024),unique=False)
    tokenized_price = db.Column(db.Float,default=0.0)
    owner =  db.Column(db.String(1024))
    investment_name = db.Column(db.String(1024))
    investor_name = db.Column(db.String(1024))
    investor_token = db.Column(db.String(1024))
    
    
class Network:
    def __init__(self):
        self.pending_transactions = []
        self.approved_transactions = []
        self.stake = []
        self.chain = [self.create_genesis_block()]
        self.senders = []
        self.money = []
        self.receipts = []
        self.market_cap = 0.0001
        
    def set_market_cap(self, value):
        self.market_cap = value
        
    def add_transaction(self,transaction):
        self.pending_transactions.append(transaction)
    
    def create_genesis_block(self):
        return PrivateBlock(0, "0",time.time(), [], "0")
   
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            if current_block.hash != current_block.calculate_hash():
                return False
            
            if current_block.previous_hash != previous_block.hash:
                return False
            
            for transaction in current_block.transactions:
                if not transaction.is_valid():
                    return False
                
        return True
    
    def get_latest_block(self):
        return self.chain[-1]
    
    def sign_packet(self,packet:bytes, key):
        hash = int.from_bytes(sha512(packet).digest(), byteorder='big')
        signature = pow(hash, key.d, key.n)
        print("Signature:", hex(signature))
        self.receipts.append(signature)
        return (signature,hex(signature))
    
    def verify_packet(self,packet:bytes, key,signature):
        hash = int.from_bytes(sha512(packet).digest(), byteorder='big')
        hashFromSignature = pow(signature, key.e, key.n)
        print("Signature valid:", hash == hashFromSignature)
        return hash == hashFromSignature
    
    def get_stake(self):
        return self.stake
    
    def get_pending(self):
        return self.pending_transactions
    
    def get_approved(self):
        return self.approved_transactions
    
    def set_transaction(self, sender_wallet, recv_wallet, value, blockchain):
        sender_user = sender_wallet.address
        recv_public_key = recv_wallet.address
        money = value
        bal = sender_wallet.balance
        new_bal = float(bal) - float(value)
        sender_wallet.balance = new_bal
        db.session.commit()
#   blockchain.pending_transactions.append({'sender':sender_wallet.address,'recv':recv_wallet.address,'amount':value})
    
    def process_transaction(self, sender_wallet, recv_wallet, value, index, coin, blockchain):
        pending = blockchain.pending_transactions
        r =  {"id":os.urandom(10),"pending":[pending]}
        blockchain.receipts.append(r)
        trans = blockchain.pending_transactions[index]
        blockchain.approved_transactions.append(trans)
        blockchain.pending_transactions.pop(index)
        result = coin.stake_coins(blockchain.approved_transactions,blockchain.pending_transactions)
        blockchain.stake.append(result)
        gained_coins = sender_wallet.coins + result
        print("gained coins", gained_coins)
        coin.market_cap += gained_coins
        blockchain.market_cap += gained_coins
        return gained_coins
    
    def get_transaction(self, sender_wallet, recv_wallet, value):
        if sender_wallet.balance <= float(value):
            bal = recv_wallet.balance #private_wallet.get_settled_cash()
            new_bal = bal + float(value)
            recv_wallet.balance = new_bal
            db.session.commit()
        else:
            bal = sender_wallet.balance
            new_bal = bal + float(value)
            sender_wallet.balance = new_bal
            db.session.commit()
   
    def proof_of_work(self,block_data, difficulty=5):
        nonce = 0
        start_time = time.time()
        prefix = '0' * difficulty
        while True:
            nonce += 1
            text = str(block_data) + str(nonce)
            hash_result = hashlib.sha256(text.encode()).hexdigest()
            if hash_result.startswith(prefix):
                end_time = time.time()
                time_taken = end_time - start_time
                return nonce, hash_result, time_taken
    
    def generate_key_pair(self):
        keyPair = rsa.generate_private_key(3,10)
        return keyPair


class Blockchain(Network):
    def __init__(self):
        super(Network).__init__()
        self.market_cap = 0.0001
        self.staked_coins = []
        self.new_coins = 0
        self.dollar_value = 0
        self.chain = [self.create_genesis_block()]
        self.receipts = {"to":[0],"from":[0],"value":[0],'txid':[0]}
        self.approved_transactions = []
        self.pending_transactions = []
        self.money = []
        self.stake = []
        self.difficulty = 5
        self.mining_reward = 100
        
    def process_receipts(self,receipts):
        while True:
            once = os.urandom(10).hex() 
            print(once)
            if once.startswith('00') or once.endswith('00'):
                total_sum = sum(self.receipts['value'])
                self.stake += total_sum
                self.receipts.clear()
                break
        return total_sum, once
    
    def get_pending(self):
        return self.pending_transactions
    
    def get_approved(self):
        return self.approved_transactions
    
    def create_genesis_block(self):
        return PrivateBlock(0, "0",time.time(), [], "0")
    
    def get_latest_block(self):
        return self.chain[-1]
    
    def generate_key_pair(self):
        keyPair = rsa.generate_private_key(3, 10)
        return keyPair
    
    def sign_packet(self,packet:bytes, key):
        from hashlib import sha512
        hash = int.from_bytes(sha512(packet).digest(), byteorder='big')
        signature = pow(hash, key.d, key.n)
        print("Signature:", hex(signature))
        self.receipts.append(signature)
        return (signature,hex(signature))
    
    def verify_packet(self,packet:bytes, key,signature):
        hash = int.from_bytes(sha512(packet).digest(), byteorder='big')
        hashFromSignature = pow(signature, key.e, key.n)
        print("Signature valid:", hash == hashFromSignature)
        return hash == hashFromSignature
    
    def proof_of_work(self,block_data, difficulty=5):

        nonce = 0
        start_time = time.time()
        prefix = '0' * difficulty
        while True:
            nonce += 1
            text = str(block_data) + str(nonce)
            hash_result = hashlib.sha256(text.encode()).hexdigest()
            if hash_result.startswith(prefix):
                end_time = time.time()
                time_taken = end_time - start_time
                return nonce, hash_result, time_taken
    
    
    
    def mine_pending_transactions(self, mining_reward_address):
        reward_tx = (None, mining_reward_address, self.mining_reward)
        self.pending_transactions.append(reward_tx)
        block = PrivateBlock(len(self.chain), self.get_latest_block().hash, int(time.time()), self.pending_transactions)
        block.hash = block.calculate_hash()  # Simple hash assignment
        self.chain.append(block)
        self.pending_transactions.clear()
        
    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)
        
    def add_block(self,block):
        self.chain.append(block)
        
    def get_balance_of_address(self, address):
        balance = 0
        
        for block in self.chain:
            for trans in block.transactions:
                if trans.from_address == address:
                    balance -= trans.amount
                    
                if trans.to_address == address:
                    balance += trans.amount
                    
        return balance
    
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            if current_block.hash != current_block.calculate_hash():
                return False
            
            if current_block.previous_hash != previous_block.hash:
                return False
            
            for transaction in current_block.transactions:
                if not transaction.is_valid():
                    return False
                
        return True
    
    
class Coin:
    def __init__(self):
        self.market_cap = 0.0001
        self.staked_coins = []
        self.new_coins = 0
        self.dollar_value = 0
        
    def process_coins(self,blockchain):
        self.new_coins += 1
        return self.new_coins
    
    def stake_coins(self, approved_transactions, pending_transactions,blockchain):
        v = self.process_coins(blockchain)
        len1 = sum(pending_transactions)
        len2 = sum(approved_transactions)
        u = (float(len1) + float(len2)) / float(v)
        return u

import hashlib
import time
class Validator():
    def __init__(self):
        super().__init__()
        self.receipt_hash = []
        self.receipt = []
        self.ledger = {}
        self.ledger_hash = {}
        
    def mine_block(self, net, sender, recv, value, index, c):
        staked_coins = net.get_market_cap()
        earned_coins = net.process_transaction(sender, recv, value, index, c)
        c.market_cap += staked_coins + earned_coins
        self.ledger[sender.get_username()] = earned_coins
        self.receipt.append(earned_coins)
        return earned_coins
    
    def process_receipts(self):
        while True:
            once = os.urandom(10).hex() 
            print(once)
            if once.startswith('00') or once.endswith('00'):
                break
        total_sum = sum(self.receipt)
        self.stake += total_sum
        self.receipt.clear()
        return total_sum, once
    
    def hashing_double(self, value):
        hashed_data = hashlib.sha256(value).hexdigest()
        return hashed_data#int.from_bytes(self.receipt_hash.update(str(value).encode()).digest(), byteorder='big')
    
    def proof_of_work(block_data, difficulty=5):

        nonce = 0
        start_time = time.time()
        prefix = '0' * difficulty
        while True:
            nonce += 1
            text = str(block_data) + str(nonce)
            hash_result = hashlib.sha256(text.encode()).hexdigest()
            if hash_result.startswith(prefix):
                end_time = time.time()
                time_taken = end_time - start_time
                return nonce, hash_result, time_taken
class ProofOfBurn:
    def __init__(self):
        self.burn_address = "0x0000000000000000000000000000000000000000"
        self.burn_records = {}
    
    def generate_burn_hash(self, user, amount):
        """
        Generate a unique hash for the burn transaction.
        """
        data = f"{user}:{amount}:{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def burn_tokens(self, user, amount):
        """
        Simulate burning tokens by recording the burn transaction.
        """
        burn_hash = self.generate_burn_hash(user, amount)
        timestamp = time.time()
        self.burn_records[burn_hash] = {
            'user': user,
            'amount': amount,
            'timestamp': timestamp,
            'burn_address': self.burn_address
        }
        return burn_hash, timestamp
    
    def verify_burn(self, burn_hash):
        """
        Verify if a burn transaction exists.
        """
        if burn_hash in self.burn_records:
            return True, self.burn_records[burn_hash]
        else:
            return False, None

        