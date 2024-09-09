#!/usr/bin/env python3

#!/usr/bin/env python3

import socket
import threading
import asyncio
import websockets

# TCP Server Implementation
class TCPServer(threading.Thread):
	def __init__(self, host, port):
		super().__init__()
		self.host = host
		self.port = port
		
	def run(self):
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.bind((self.host, self.port))
		server_socket.listen(1)
		print(f"TCP server listening on {self.host}:{self.port}")
		
		conn, address = server_socket.accept()
		print("Connection from:", address)
		while True:
			data = conn.recv(1024).decode()
			if not data:
				break
			print("Received from TCP client:", data)
			response = input(" -> ")
			conn.send(response.encode())
		conn.close()
		
# WebSocket Server Implementation
class WebSocketServer:
	def __init__(self, host, port):
		self.host = host
		self.port = port
		
	async def websocket_handler(self, websocket, path):
		async for message in websocket:
			print(f"WebSocket received: {message}")
			await websocket.send("Hello from server")
			
	async def run_websocket_server(self):
		async with websockets.serve(self.websocket_handler, self.host, self.port):
			await asyncio.Future()  # Run forever
			
	def start(self):
		asyncio.run(self.run_websocket_server())
		
# Main Function to Start Servers
if __name__ == "__main__":
	host = '192.168.1.237'
	tcp_port = 8000
	ws_port = 8001
	
	tcp_server = TCPServer(host, tcp_port)
	tcp_server.start()
	
	ws_server = WebSocketServer(host, ws_port)
	ws_thread = threading.Thread(target=ws_server.start)
	ws_thread.start()
	
	tcp_server.join()
	ws_thread.join()
	