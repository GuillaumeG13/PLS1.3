import socket
import threading


class ClientThread(threading.Thread):
	def __init__(self, sock, ip, port, callback):
		super(ClientThread, self).__init__()
		self.sock = sock
		self.ip = ip
		self.port = port
		self.callback = callback
		print("[+] Nouveau thread : ip " + format(self) + "\n")

	def __str__(self):
		return self.ip + "::" + format(self.port)

	def run(self):
		"""Function run as a thread"""
		print("[s] Start thread : " + format(self))

		self.callback(self.sock)


class SocketTLS:
	def __init__(self, ip="127.0.0.1", port=1799, server=True, workers=5, callback=None):
		self.ip = ip
		self.port = port
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server = server
		self.workers = workers
		self.data = ""
		self.callback = callback

		if not server:
			self.user_sock = self.sock

	def initialize_connection(self):
		"""Start client as well as sever"""
		if self.server:
			try:
				self.bind()
			except:
				print("Binding error\n")
				exit(0)
			print("Server bind ...\n")
			try:
				self.listen()
			except:
				print("Server listening error\n")
				exit(0)
			print("Server is listening ...\n")
			while(1):
				self.accept()
				print("Connection has been accepted !\n")
		else:
			self.connect()
			print("Client successfully connected")

	def connect(self):
		self.sock.connect((self.ip, self.port))

	def bind(self):
		self.sock.bind((self.ip, self.port))

	def listen(self):
		self.sock.listen(self.workers)

	def accept(self):
		# Accept connection and get the socket
		try:
			socket = self.sock.accept()
		except:
			print("Server ACCEPT error\n")
			exit(0)
		self.user_sock = socket[0]

		# Launch the connection as a thread which will apply the callback function
		thread = ClientThread(self, socket[1][0], socket[1][1], self.callback)
		thread.start()
		return socket

	def update(self, data):
		""" Update the data that shall be sent through the send function"""
		self.data = data
		return self.data

	def send(self):
		"""Send content of self.data through tcp socket"""
		self.user_sock.send(str.encode(self.data))
		return format(self.data)

	def receive(self):
		"""Receive data from tcp socket and store it in self.data"""
		self.data = self.user_sock.recv(9999999)
		return self.data
