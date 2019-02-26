from tls_socket import *
from math import floor
from hash import encrypt_string
from hkdf import *
from binascii import unhexlify
import subprocess




class TLS:
	def __init__(self, curve, serveur=True):
		self.curve = curve
		self.callback = None
		self.socket = SocketTLS(ip="127.0.0.1", port=1799, server=False, workers=5)
		self.messageHelloList = []
		self.server_key_exchange = ""
		self.server_handshake_key = ""
		self.public_key = ""
		self.private_key = ""
		self.external_key = ""  # It's the key related to the other point of connection
		self.secret = ""
		self.serveur = serveur

		self.client_handshake_iv = ""
		self.client_handshake_key = ""
		self.server_handshake_iv = ""
		self.server_handshake_key = ""
		self.handshake_secret = ""


	def hello(self, params):

		random = params['random']
		version = params['version']
		session_id = params['session_id']
		cipher_suites = params['cipher_suites']
		compression_method = params['compression_method']
		extension_length = params['extension_length']

		data = version + random + session_id + cipher_suites + compression_method + extension_length
		# Length of data in bytes
		size = int(len(data) / 2)

		handshake_header = params['handshake_header'] + TLS.format_length(size, 6)
		header = params['header'] + TLS.format_length(size + 4, 4) + handshake_header

		msg = header + data
		self.messageHelloList.append(msg[5:])

		# Send the message through the socket
		self.socket.update(msg)
		self.socket.send()

		return data

	def receive_hello(self):
		msg = self.socket.receive()
		self.messageHelloList.append(msg[5:])

	def receive_external_key(self):
		"""Publish and get public keys"""
		if self.serveur:
			self.socket.update(self.public_key)
			self.socket.send()
			self.external_key = self.socket.receive()
		else:
			self.external_key = self.socket.receive()
			self.socket.update(self.public_key)
			self.socket.send()

	def server_handshake_key_generation(self):
		# Multiplication courbe ECC
		# TODO : Maxime et Marcou
		# self.receive_external_key()

		# self.secret = hex(int(self.private_key, 16) * int(self.external_key, 16)).split('0x')[1]
		# hello_hash = encrypt_string("".join(self.messageHelloList))
		hello_hash = "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5"
		keys = subprocess.check_output("windaube " + hello_hash + " " + self.secret, shell=True)
		[self.client_handshake_key, self.server_handshake_key, self.client_handshake_iv, self.server_handshake_iv] = keys.decode().split('plop')[1].split(' ')[1:-1]
		return self.client_handshake_key, self.server_handshake_key, self.client_handshake_iv, self.server_handshake_iv



	def initialize_connection(self):
		self.socket.initialize_connection()

	@staticmethod
	def format_length(length, size):
		"""Give the hexadecimal notation of decimal length on size digits
			format_length(2, 4) = 0002
			format_length(16,3) = 010
		"""
		formatted = hex(length).split('0x')[1]
		while len(formatted) < size:
			formatted = '0' + formatted
		return formatted
