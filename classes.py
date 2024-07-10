#!/usr/bin/env python3
import hashlib
from ecdsa import SigningKey, SECP256k1
import binascii as bina
import codecs
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
import json
from hashlib import sha512
from collections import defaultdict
import hashlib 
import random
import os
import datetime as dt


class PrivateInvestment:
	def __init__(self, investment_name, value, owner):
		self.investment_name = investment_name
		self.market_cap = 0
		self.investors = []
		self.sum_of_investors = 0
		self.receipt = os.urandom(10)
	
	def get_name(self):
		return self.investment_name
	
	def get_coin(self):
		return self.coins_value
	
	def get_marketcap(self):
		return self.market_cap
	
	def get_owner(self):
		return self.owner
	
	def get_investors(self):
		return self.investors
	
	def get_sum_investors(self):
		return self.sum_of_investors

	def get_file(self):
		return self.file
	
class PrivateWallet:
	def __init__(self):
		self.pending_transactions = {}
		self.approved_transactions = {}
		self.active_investments = []
		self.investment_vector = []
		self.settled_cash = 100
		self.coins = 0
		
	def generate_key_pair(self):
		keyPair = _rsa.generate_private_key(3, 10)
		return keyPair
	
	def sign_packet(self,packet:bytes, key):
		hash = int.from_bytes(sha512(packet).digest(), byteorder='big')
		signature = pow(hash, key.d, key.n)
		print("Signature:", hex(signature))
		return (signature,hex(signature))
		
	def verify_packet(self,packet:bytes, key, signature):
		hash = int.from_bytes(sha512(packet).digest(), byteorder='big')
		hashFromSignature = pow(signature, key.e, key.n)
		print("Signature valid:", hash == hashFromSignature)
		return hash == hashFromSignature
	
	def generate_new_address(self):
		new_key_pair = SigningKey.generate(curve=SECP256k1)
		return new_key_pair.verifying_key.to_string().hex()
		
	def set_active_investment(self, name, value):
		self.active_investments[name] = value
		
	def set_settled_cash(self, value):
		self.settled_cash = value
		
	def set_coins(self, value):
		self.coins = value
	
	def get_settled_cash(self):
		return self.settled_cash
	
	def get_coins(self):
		return self.coins
	
	def sell_coins(self, amount):
		self.settled_cash += amount
		
	def buy_coins(self, amount):
		self.settled_cash -= amount
		self.coins += amount
		
	def get_total_investments(self):
		return sum(self.investment_vector)

	def get_active_investments(self):
		return self.active_investments

class Balance:
	def __init__(self):
		self.active_investments = {'name':[],'amount':[],'tokenized_amount':[]}
		self.investment_vector = []
		self.settled_cash = 100
		self.coins = 0
		
		
	def set_active_investment(self, name, value):
		self.active_investments[name] = value
		
	def set_settled_cash(self, value):
		self.settled_cash = value
		
	def set_coins(self, value):
		self.coins = value
		
	def get_settled_cash(self):
		return self.settled_cash
	
	def get_coins(self):
		return self.coins
	
	def sell_coins(self, amount):
		self.settled_cash += amount
		
	def buy_coins(self, amount):
		self.settled_cash -= amount
		self.coins += amount
		
	def get_total_investments(self):
		return sum(self.investment_vector)
	
	def get_active_investments(self):
		return self.active_investments
	
class Client:
	def __init__(self):
		self.username = ""
		self.password = ""
		self.balance = Balance()
		self.public_key = ""
		self.stake = 0
		
	def set_stake(self, value):
		self.stake = value
		
	def set_username(self, value):
		self.username = value
		
	def set_password(self, value):
		self.password = value
		
	def set_public_key(self, value):
		self.public_key = value
		
	def get_stake(self):
		return self.stake
	
	def get_username(self):
		return self.username
	
	def get_password(self):
		return self.password
	
	def get_public_key(self):
		return self.public_key
	
	def make_investment(self, value, invest):
		invest.investors.append({'name':invest.investment_name,'value':value}) #[invest.investment_name] = value
		self.wallet.active_investments.append(invest)
		bal = self.wallet.get_settled_cash()
		new_bal = bal - float(invest.get_coin())
		self.wallet.set_settled_cash(new_bal)
		self.wallet.investment_vector.append(value)
		invest.market_cap += value
		invest.sum_of_investors += 1
		
	def sell_investment(self, value, invest):
		self.wallet.active_investments[invest.investment_name] = 0
		bal = self.wallet.get_settled_cash()
		invest.market_cap -= bal
		
	def convert_stake(self):
		s = self.stake
		self.wallet.coins += s
		self.stake = 0
		
class Coin:
	def __init__(self):
		self.market_cap = 0.0001
		self.staked_coins = []
		self.new_coins = 0
		self.dollar_value = 0
		
	def process_coins(self):
		self.new_coins += 1
		return self.new_coins
	
	def set_dollar_value(self, value):
		self.dollar_value = value
		
	def get_dollar_value(self):
		return self.dollar_value
	
	def stake_coins(self, approved_transactions, pending_transactions, sender):
		v = self.process_coins()
		len1 = len(pending_transactions)
		len2 = len(approved_transactions)
		pending_sum = sum(pending_transactions)
		approved_sum = sum(approved_transactions)
		total_sum = pending_sum + approved_sum
		u = (len1 + len2) / total_sum * v
		return u
	
class Network:
	def __init__(self):
		self.pending_transactions = []
		self.approved_transactions = []
		self.stake = []
		self.web = defaultdict(float)
		self.senders = []
		self.money = []
		self.receipts = []
		self.market_cap = 0.0001
		
	def set_market_cap(self, value):
		self.market_cap = value
			
	def add_transaction(self,transaction):
		self.pending_transactions.append(transaction)
		
	def get(self):
		for i in range(len(self.senders)):
			print("senders\t", self.senders[i])
			print("recipients\t", self.recipients[i])
			print("money\t", self.money[i])
	
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
			
	def set_transaction(self, sender_wallet, recv_wallet, value):
		sender_user = sender_wallet.address
		recv_public_key = recv_wallet.address
		money = value
		bal = sender_wallet.balance
		new_bal = float(bal) - float(value)
		sender_wallet.balance = new_bal
		
	def process_transaction(self, sender_wallet, recv_wallet, value, index, coin, blockchain):
		pending = blockchain.pending_transactions
		r =  {"id":os.urandom(10),"pending":[pending]}
		blockchain.receipts.append(r)
		trans = blockchain.pending_transactions[index]
		blockchain.approved_transactions.append(trans)
		blockchain.pending_transactions.pop(index)
		result = coin.stake_coins(blockchain.approved_transactions,blockchain.money, sender)
		blockchain.stake.append(result)
		gained_coins = sender_wallet.coins + result
		print("gained coins", gained_coins)
		coin.market_cap += gained_coins
		blockchain.market_cap += gained_coins
		return gained_coins
	
	def get_transaction(self, sender_wallet, recv_wallet, value):
		if sender_wallet.balance >= float(value):
			bal = recv_wallet.balance #private_wallet.get_settled_cash()
			new_bal = bal + float(value)
			recv_wallet.balance = new_bal
			db.session.commit()
		else:
			bal = sender_wallet.balance
			new_bal = bal + float(value)
			sender_wallet.balance = new_bal
			db.session.commit()
			
class Validator(Client):
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
		total_sum = sum(self.receipt)
		self.stake += total_sum
		self.receipt.clear()
		return total_sum
	
	def hashing_double(self, value):
		hashed_data = hashlib.sha256(value).hexdigest()
		return hashed_data#int.from_bytes(self.receipt_hash.update(str(value).encode()).digest(), byteorder='big')
	
class PrivateBlock:
	def __init__(self, index, previous_hash, timestamp, transactions, hash=None):
		self.index = index
		self.previous_hash = previous_hash
		self.timestamp = timestamp
		self.transactions = transactions
		self.hash = hash or self.calculate_hash()
		
	def calculate_hash(self):
		return hashlib.sha256(str(self.index).encode())
		
class Blockchain(Network):
	def __init__(self):
		super(Network).__init__()
		self.chain = [self.create_genesis_block()]
		self.transactions_pending_verification = []
		self.approved_transactions = []
		self.pending_transactions = []
		self.difficulty = 4
		self.mining_reward = 100
	
 
	def get_unverified(self):
		return self.transactions_pending_verification

	def get_pending(self):
		return self.pending_transactions
	
	def get_approved(self):
		return self.chain
	
	def create_genesis_block(self):
		return PrivateBlock(0, "0", dt.date.today(), [], "0")
	
	def get_latest_block(self):
		return self.chain[-1]
	
	def mine_pending_transactions(self, mining_reward_address):
		reward_tx = Transaction(None, mining_reward_address, self.mining_reward)
		self.pending_transactions.append(reward_tx)
		block = Block(len(self.chain), self.get_latest_block().hash, int(time.time()), self.pending_transactions)
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
		