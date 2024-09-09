#!/usr/bin/env python3

import socket
import asyncio
import threading
import logging
from websockets import serve
from websockets.uri import parse_uri
from websockets.client import connect
import sys
from tornado.httpclient import AsyncHTTPClient


# Configure logging
logger = logging.getLogger('websockets')
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

class WebSocketServer:
	def __init__(self, port, host):
		self.signals = []
		self.messages = []
		self.PORT = port
		self.HOST = host
		
	async def websocket_handler(self, websocket, path):
		async for message in websocket:
			logger.info(f"WebSocket received: {message} from {websocket.remote_address}")
			await websocket.send("Hello from server")
			self.signals.append(websocket.remote_address)
			self.messages.append(message)
			
	async def run_websocket_server(self, host, port):
		async with serve(self.websocket_handler, host, port):
			await asyncio.Future()  # Run forever
			
	def start_server(self):
		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		loop.run_until_complete(self.run_websocket_server(self.HOST, self.PORT))
		
def main():
	host = '0.0.0.0'
	base_port = 8000
	num_servers = 100
	
	servers = [WebSocketServer(base_port + i, host) for i in range(num_servers)]
	threads = [threading.Thread(target=server.start_server) for server in servers]
	
	for thread in threads:
		thread.start()
		
	for thread in threads:
		thread.join()
		
class Server(AsyncHTTPClient):
	def __init__(self):
		self.event = threading.Event()
		
	def listen(self):
		self.listen(8888)
	
	def start(self):
		res = self.fetch('http://www.google.com')
		self.event(res)
		return res.request.body
		
	def run(self,):
		server = '127.0.0.1'#'137.184.226.245'
		ssh_port = 2222
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind((server, ssh_port))
			sock.listen(100)
			print('[+] Listening for connection ...')
			client, addr = sock.accept()
			while True:
				data = input("==>\t")
				client.send(data.encode())
		except Exception as e:
			print('[-] Listen failed: ' + str(e))
			sys.exit(1)
		else:
			print(f'[+] Got a connection! from {addr}')
		
network = []			
if __name__ == '__main__':
	server = Server()
	main_thread = threading.Thread(target=main)
	server_thread = threading.Thread(target=server.run)
#	web_thread = threading.Thread(target=server.start)
	main_thread.start()
	server_thread.start()
#	web_thread.start()
	main_thread.join()
	server_thread.join()
#	web_thread.join()
	
	