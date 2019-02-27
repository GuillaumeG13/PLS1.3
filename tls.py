from tls_socket import *
import subprocess
import hashlib
from binascii import unhexlify
from constants import *
from message_utils import *

class TLS:
	def __init__(self, curve, serveur=True):
		self.curve = curve
		self.callback = None
		self.socket = SocketTLS(ip="127.0.0.1", port=1799, server=False, workers=5)
		self.messageHelloList = []

		self.public_key = ""
		self.private_key = ""
		self.external_key = ""  # It's the key related to the other point of connection
		self.secret = ""        # Secret shared through DeffieHellman
		self.serveur = serveur

		self.client_handshake_iv = ""
		self.client_handshake_key = ""
		self.server_handshake_iv = ""
		self.server_handshake_key = ""
		self.handshake_secret = ""

	def initialize_connection(self):
		self.socket.initialize_connection()

	def get_extension_key_share(self):
		"""
		00 33 - assigned value for extension "Key Share"
		00 24 - 0x24 (36) bytes of "Key Share" extension data follows
		00 1d - assigned value for x25519 (key exchange via curve25519)
		00 20 - 0x20 (32) bytes of public key follows
		9f d7 ... b6 15 - public key from the step "Exchange Generation"
		"""
		return EXTENSIONS.KEY_SHARE.value + dec_to_hexa(36, 2) + X25519_CURVE_KEY + dec_to_hexa(b_len(self.public_key), 2) + self.public_key 


	def hello(self, params):
		random = params['random']
		session_id = params['session_id']
		cipher_suites = params['cipher_suites']
		compression_method = params['compression_method']

		key_share_extension = self.get_extension_key_share()
		extension_length = dec_to_hexa(b_len(key_share_extension), 2)

		data = PROTOCOL_VERSION + random + session_id + cipher_suites + compression_method + extension_length + key_share_extension
		data_length = dec_to_hexa(b_len(data), 3)

		handshake_header =  HANDSHAKE_MESSAGE_TYPES.SERVER_HELLO.value if self.serveur else HANDSHAKE_MESSAGE_TYPES.CLIENT_HELLO.value + data_length

		handshake_length = dec_to_hexa(b_len(handshake_header + data), 2)
		record_header = RECORD_TYPES.HANDSHAKE.value + PROTOCOL_VERSION + handshake_length

		msg = record_header + handshake_header + data
		self.messageHelloList.append(msg[5:])

		self.socket.update(msg)
		self.socket.send()

		return data

	def receive_hello(self):
		msg = self.socket.receive()
		self.messageHelloList.append(msg[5:])

	def verify_certificates(self):
		# TODO
		pass

	def generate_asymetrique_keys(self):
		# TODO : Maxime & Marcou
		self.private_key = ""
		self.public_key = ""

	def publish_public_key(self):
		# TODO
		pass
	
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

	def handshake_key_generation(self):
		# Multiplication courbe ECC
		# TODO : Maxime et Marcou
		# self.receive_external_key()
		# self.secret = hex(int(self.private_key, 16) * int(self.external_key, 16)).split('0x')[1]

		self.messageHelloList = ["010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304", "020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304"]

		hello_hash = hashlib.sha256(unhexlify("".join(self.messageHelloList))).hexdigest()
		
		print("Hello hash : " + hello_hash)

		keys = subprocess.check_output("windaube " + hello_hash + " " + self.secret, shell=True)
		[self.client_handshake_key, self.server_handshake_key, self.client_handshake_iv, self.server_handshake_iv] = keys.decode().split('plop')[1].split(' ')[1:-1]
		return self.client_handshake_key, self.server_handshake_key, self.client_handshake_iv, self.server_handshake_iv

	def handshake_encryption(self):
		pass