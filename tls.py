from tls_socket import *
import subprocess
import hashlib
from binascii import unhexlify

class TLS:
	def __init__(self, curve, serveur=True, certificate=""):
		self.curve = curve
		self.callback = None
		self.socket = SocketTLS(ip="127.0.0.1", port=1799, server=False, workers=5)
		self.messageHelloList = []
		self.messageHandshake = []

		self.public_key = ""
		self.private_key = ""
		self.external_key = ""  # It's the key related to the other point of connection
		self.secret = ""        # Secret shared through DeffieHellman
		self.serveur = serveur

		self.client_handshake_iv = b""
		self.client_handshake_key = b""
		self.server_handshake_iv = b""
		self.server_handshake_key = b""
		self.handshake_secret = b""

		self.certificate = certificate


	def initialize_connection(self):
		self.socket.initialize_connection()

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

	def generate_asymetrique_keys(self):
		# TODO : Maxime & Marcou
		self.private_key = ""
		self.public_key = ""

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

	def hkdf_extract(self, salt, input_key_material):
		import hkdf
		if input_key_material is None:
			input_key_material = b"\x00" * hashlib.sha256().digest_size
		return hkdf.hkdf_extract(salt, input_key_material, hashlib.sha256)

	def hkdf_label(self, label, context, length):
		label = b"tls13 " + label
		return (
				length.to_bytes(2, "big")
				+ len(label).to_bytes(1, "big")
				+ label
				+ len(context).to_bytes(1, "big")
				+ context
		)


	def hkdf_expand_label(self, secret, label, context, length):
		import hkdf
		hkdf_label = self.hkdf_label(label, context, length)
		return hkdf.hkdf_expand(secret, hkdf_label, length, hashlib.sha256)

	def key_expansion(self, hash):
		hello_hash = unhexlify(hash)
		empty_hash = hashlib.sha256(b'').digest()
		early_secret = self.hkdf_extract(b'\x00', None)
		derived_secret = self.hkdf_expand_label(early_secret, b"derived", empty_hash, 32)

		handshake_secret = self.hkdf_extract(derived_secret, unhexlify(self.secret))
		client_handshake_traffic_secret = self.hkdf_expand_label(handshake_secret, b"c hs traffic", hello_hash, 32)
		server_handshake_traffic_secret = self.hkdf_expand_label(handshake_secret, b"s hs traffic", hello_hash, 32)
		self.client_handshake_key = self.hkdf_expand_label(client_handshake_traffic_secret, b"key", b"", 16)
		self.server_handshake_key = self.hkdf_expand_label(server_handshake_traffic_secret, b"key", b"", 16)
		self.client_handshake_iv = self.hkdf_expand_label(client_handshake_traffic_secret, b"iv", b"", 12)
		self.server_handshake_iv = self.hkdf_expand_label(server_handshake_traffic_secret, b"iv", b"", 12)

	def handshake_key_generation(self):
		# Multiplication courbe ECC
		# TODO : Maxime et Marcou
		# self.receive_external_key()
		# self.secret = hex(int(self.private_key, 16) * int(self.external_key, 16)).split('0x')[1]
		# hello_hash = hashlib.sha256(unhexlify("".join(self.messageHelloList))).hexdigest()

		hello_hash = "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5"
		print("Hello hash : " + hello_hash)
		self.key_expansion(hello_hash)
		return self.client_handshake_key.hex(), self.server_handshake_key.hex(), self.client_handshake_iv.hex(), self.server_handshake_iv.hex()

	def send_certificate(self, params):
		# First message is related to certificate
		data = self.format_length(len(self.certificate) / 2, 6) + self.certificate + params['certificate_extension']
		data = params['request_context'] + self.format_length(len(data)/2, 6) + data
		data = '0b' + self.format_length(len(data) / 2, 6) + data

		self.socket.update(data)
		print("Certificate : " + data)
		self.socket.send()

		# This message contain information to verify certificate information
		data = hashlib.sha256(str.encode(data)).hexdigest()
		# TODO : Signature with elliptical curve
		# data = self.curve.sign(data)
		data = '0f' + self.format_length(len(data)/2, 6) + data
		self.socket.update(data)
		self.socket.send()
		print("Verify Certificate : " + data)

	def verify_certificates(self):
		# TODO
		pass

	def server_handshake_finished(self):
		pass


	def data_encryption(self):
		# TODO : Julie AES
		# La data à chiffrer doit etre placé dans self.socket.data
		# On la met a jour avec self.socket.update()
		# On l'envoie avec self.socket.send()
		pass

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
