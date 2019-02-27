from tls_socket import *
import subprocess
import hashlib
from binascii import unhexlify
from constants import *
from message_utils import *
import hmac

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

		self.client_handshake_traffic_secret = b""
		self.server_handshake_traffic_secret = b""
		self.client_handshake_iv = b""
		self.client_handshake_key = b""
		self.server_handshake_iv = b""
		self.server_handshake_key = b""
		self.handshake_secret = b""

		self.client_application_traffic_secret = b""
		self.server_application_traffic_secret = b""
		self.client_application_iv = b""
		self.client_application_key = b""
		self.server_application_iv = b""
		self.server_application_key = b""
		self.handshake_secret = b""

		self.certificate = certificate

	def run(self):
		if self.serveur:
			self.callback = self.run_as_serveur
			self.initialize_connection()
		else:
			self.run_as_client()

	def run_as_serveur(self):
		self.generate_asymetrique_keys()
		self.receive_hello()
		params = {
			'random': '20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
			'session_id': '20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
			'cipher_suites': '1301',
			'compression_method': '00',
		}
		self.hello(params)
		self.handshake_key_generation()

		params = {
			'request_context': '00',
			'certificate_extension': '0000',
		}
		self.send_certificate(params)
		self.server_handshake_finished()
		self.application_key_generation()

	def run_as_client(self):
		pass

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

		handshake_header = HANDSHAKE_MESSAGE_TYPES.SERVER_HELLO.value if self.serveur else HANDSHAKE_MESSAGE_TYPES.CLIENT_HELLO.value + data_length

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
		self.messageHandshake.append(msg[5:])

	def generate_asymetrique_keys(self):
		# TODO : Maxime & Marcou
		self.private_key = ""
		self.public_key = ""



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

		self.handshake_secret = self.hkdf_extract(derived_secret, unhexlify(self.secret))
		self.client_handshake_traffic_secret = self.hkdf_expand_label(self.handshake_secret, b"c hs traffic", hello_hash, 32)
		self.server_handshake_traffic_secret = self.hkdf_expand_label(self.handshake_secret, b"s hs traffic", hello_hash, 32)
		self.client_handshake_key = self.hkdf_expand_label(self.client_handshake_traffic_secret, b"key", b"", 16)
		self.server_handshake_key = self.hkdf_expand_label(self.server_handshake_traffic_secret, b"key", b"", 16)
		self.client_handshake_iv = self.hkdf_expand_label(self.client_handshake_traffic_secret, b"iv", b"", 12)
		self.server_handshake_iv = self.hkdf_expand_label(self.server_handshake_traffic_secret, b"iv", b"", 12)

	def handshake_key_generation(self):
		# Multiplication courbe ECC
		# TODO : Maxime et Marcou
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
		finished_key = self.hkdf_expand_label(self.server_handshake_traffic_secret, b"finished", b"", 32)
		finished_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
		verify_data = hmac.new(finished_key, finished_hash).digest()
		print("Verify Data : " + verify_data.hex())

		data = "14" + self.format_length(len(verify_data) / 2, 6) + verify_data.hex()
		self.socket.update(data)
		self.socket.send()

	def key_expansion_application(self, hash):
		empty_hash = hashlib.sha256(b'').digest()
		derived_secret = self.hkdf_expand_label(self.handshake_secret, b"derived", empty_hash, 32)

		master_secret = self.hkdf_extract(derived_secret, None)
		client_application_traffic_secret = self.hkdf_expand_label(master_secret, b"c ap traffic", hash, 32)
		self.server_application_traffic_secret = self.hkdf_expand_label(master_secret, b"s ap traffic", hash, 32)
		self.client_application_key = self.hkdf_expand_label(client_application_traffic_secret, b"key", b"", 16)
		self.server_application_key = self.hkdf_expand_label(self.server_application_traffic_secret, b"key", b"", 16)
		self.client_application_iv = self.hkdf_expand_label(client_application_traffic_secret, b"iv", b"", 12)
		self.server_application_iv = self.hkdf_expand_label(self.server_application_traffic_secret, b"iv", b"", 12)

		return self.client_application_key.hex(), self.server_application_key.hex(), self.client_application_iv.hex(), self.server_application_iv.hex()

	def application_key_generation(self):
		# handshake_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
		handshake_hash = unhexlify("22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b")
		self.handshake_key_generation()
		return self.key_expansion_application(handshake_hash)


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
