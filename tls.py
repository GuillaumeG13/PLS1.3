from tls_socket import *
import subprocess
import hashlib
from binascii import unhexlify
from constants import *
from message_utils import *
import hmac
import AEScryp as AES

class TLS:
	def __init__(self, curve, serveur=True, certificate=""):
		self.curve = curve
		self.callback = None
		self.socket = SocketTLS(ip="127.0.0.1", port=1799, server=serveur, workers=5)
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
			self.socket.callback = self.run_as_serveur
			self.initialize_connection()
		else:
			self.run_as_client()

	def run_as_client(self):
		self.generate_asymetrique_keys()
		params = {
			'random': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
			'session_id': '20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
			'cipher_suites': '1301',
			'compression_method': '00',
		}
		self.hello(params)
		self.receive_hello()
		self.handshake_key_generation()
		self.verify_certificates()
		self.send_client_handshake_finished()

	def run_as_serveur(self, sock):
		self.generate_asymetrique_keys()
		self.receive_hello()
		params = {
			'random': '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
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
		self.application_key_generation()
		self.receive_client_handshake_finished()
		# Receive client handshake finished


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


	# Tested for server
	def hello(self, params):
		"""
		Tested for server part
		:param params:
		:return:
		"""
		random = params['random']
		session_id = params['session_id']
		cipher_suites = params['cipher_suites']
		compression_method = params['compression_method']

		key_share_extension = self.get_extension_key_share() + '002b00020304'
		extension_length = dec_to_hexa(b_len(key_share_extension), 2)

		data = PROTOCOL_VERSION + random + session_id + cipher_suites + compression_method + extension_length + key_share_extension
		print(len(data))
		data_length = self.format_length(len(data)/2, 6)

		handshake_header = HANDSHAKE_MESSAGE_TYPES.SERVER_HELLO.value if self.serveur else HANDSHAKE_MESSAGE_TYPES.CLIENT_HELLO.value
		handshake_header += data_length

		handshake_length = self.format_length(len(handshake_header + data)/2, 4)
		record_header = RECORD_TYPES.HANDSHAKE.value + PROTOCOL_VERSION + handshake_length

		msg = record_header + handshake_header + data
		self.messageHelloList.append(msg[10:])
		self.messageHandshake.append(msg[10:])
		print("Hello Message : " + msg)

		self.socket.update(msg)
		self.socket.send()

		return data

	def receive_hello(self, message):
		self.messageHelloList.append(message[5:])
		""" 
		Record Header: 5 bytes
		Handshake Header: 4 bytes
		Client Version: 2 bytes
		Client Random: 32 bytes
			--> 43 bytes
		Session ID length: 1 byte
		Cipher Suites length: 2 bytes
		Compression Methods length: 1 byte
		"""
		random_index = 11

		session_id_index = random_index + 32
		n_session_id = hexa_to_dec(get_bytes(message, session_id_index, 1))

		extensions_index = session_id_index + 1 + n_session_id
		extension_type = get_bytes(message, extensions_index + 2, 2)
		print(extension_type)

		if extension_type != EXTENSIONS.KEY_SHARE.value :
			raise Exception('There should be only one extension in Hello: Key Share ("00 33")')

		"""
		Extensions Length: 2 bytes
		Extension Type: 2 bytes
		Extension Length: 2 bytes
		"""
		key_share_index = extensions_index + 2
		n_key_share = hexa_to_dec(get_bytes(message, key_share_index - 2, 2))


		hello = dict()
		hello['random'] = get_bytes(message, random_index, 32)
		hello['session_id'] = get_bytes(message, session_id_index, n_session_id)
		hello['public_key'] = get_bytes(message, key_share_index, n_key_share)

		print("hello object: ")
		print(hello)

		return hello


	def generate_asymetrique_keys(self):
		# TODO : Maxime & Marcou
		if not self.serveur:
			self.private_key = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
			self.public_key = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
		else:
			self.private_key = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
			self.public_key = "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615"

	# Tested
	def hkdf_extract(self, salt, input_key_material):
		import hkdf
		if input_key_material is None:
			input_key_material = b"\x00" * hashlib.sha256().digest_size
		return hkdf.hkdf_extract(salt, input_key_material, hashlib.sha256)

	# Tested
	def hkdf_label(self, label, context, length):
		label = b"tls13 " + label
		return (
				length.to_bytes(2, "big")
				+ len(label).to_bytes(1, "big")
				+ label
				+ len(context).to_bytes(1, "big")
				+ context
		)

	# Tested
	def hkdf_expand_label(self, secret, label, context, length):
		import hkdf
		hkdf_label = self.hkdf_label(label, context, length)
		return hkdf.hkdf_expand(secret, hkdf_label, length, hashlib.sha256)

	# Tested
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

	# Tested
	def handshake_key_generation(self):
		# Multiplication courbe ECC
		# TODO : Maxime et Marcou
		# self.secret = hex(int(self.private_key, 16) * int(self.external_key, 16)).split('0x')[1]
		hello_hash = hashlib.sha256(unhexlify("".join(self.messageHelloList))).hexdigest()

		# hello_hash = "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5"
		print("Hello hash : " + hello_hash)
		self.key_expansion(hello_hash)
		return self.client_handshake_key.hex(), self.server_handshake_key.hex(), self.client_handshake_iv.hex(), self.server_handshake_iv.hex()

	# Tested
	def send_certificate(self, params):
		# First message is related to certificate
		data = self.format_length(len(self.certificate) / 2, 6) + self.certificate + params['certificate_extension']
		data = params['request_context'] + self.format_length(len(data)/2, 6) + data
		data = '0b' + self.format_length(len(data) / 2, 6) + data

		# This message contain information to verify certificate information
		data_verify = hashlib.sha256(str.encode(data)).hexdigest()
		# TODO : Signature with elliptical curve
		# data = self.curve.sign(data)
		data_verify += '0f' + self.format_length(len(data)/2, 6) + data_verify + self.send_server_handshake_finished()

		# data = self.data_encryption(data + data_verify, self.server_handshake_key, self.server_handshake_iv)
		data += data_verify
		header = '170303' + self.format_length(len(data)/2, 4) # Add data size verification data < 16^5 - 1
		data = header + data
		print("Wrapper data : " + data)
		self.socket.update(data)
		# self.socket.send()
		self.messageHandshake.append(data)

	def verify_certificates(self):
		self.socket.receive()
		data = self.socket.data
		type = data[0:2]
		cipher = data[8:]
		body = ""
		# body = self.decrypt(cipher, self.server_handshake_key, self.server_handshake_iv)

		certificate_type = body[0:2]
		certificate_size = int(body[8:14], 16)
		index = (14 + certificate_size)
		certificate = body[14: index]
		# TODO : Verify the content of the certificate

		verify_size = int(body[index+6:index+12],16)
		verify = body[index+12: index+12+verify_size]
		# TODO : Verify Signature

		index = index+12+verify_size
		finish_size = int(body[index+2:index+6],16)
		finish = body[index+6:index+6+finish_size]

		self.receive_server_handshake_finished(finish)

	def send_client_handshake_finished(self):
		finished_key = self.hkdf_expand_label(self.client_handshake_traffic_secret, b"finished", b"", 32)
		finished_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
		verify_data = hmac.new(finished_key, finished_hash).hexdigest()
		data = self.data_encryption(verify_data, self.client_handshake_key, self.client_handshake_iv)
		header = "1703030035" + self.format_length(len(data) / 2, 4)
		data = data + header
		self.socket.update(data)
		self.socket.send()

	# Tested
	def send_server_handshake_finished(self):
		finished_key = self.hkdf_expand_label(self.server_handshake_traffic_secret, b"finished", b"", 32)
		finished_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
		verify_data = hmac.new(finished_key, finished_hash).digest()

		data = "14" + self.format_length(len(verify_data.hex()) / 2, 6) + verify_data.hex()

		print("Challenge Frame : " + data)
		return data

	# Tested
	def receive_client_handshake_finished(self):
		self.socket.receive()
		data = ""
		# data = self.data_decrypt(self.socket.data, self.client_handshake_key, self.client_handshake_iv)
		if data[:1] == '14':
			verify_data = data[8:]
			finished_key = self.hkdf_expand_label(self.client_handshake_traffic_secret, b"finished", b"", 32)
			finished_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
			if verify_data != hmac.new(finished_key, finished_hash).hexdigest():
				raise ValueError("Verify data mismatch")

	# Tested
	def receive_server_handshake_finished(self, finish):
		finished_key = self.hkdf_expand_label(self.server_handshake_traffic_secret, b"finished", b"", 32)
		finished_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
		verify_data = hmac.new(finished_key, finished_hash).digest()

		if finish != verify_data:
			raise ValueError('Challenge failed')

	# Tested
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

	# Tested
	def application_key_generation(self):
		# handshake_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
		handshake_hash = unhexlify("22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b")
		return self.key_expansion_application(handshake_hash)

	@staticmethod
	def data_encryption(data, key, iv):
		aes = AES.AES(data, key, iv)
		cipher = aes.encrypt(galois=AES.galois, rcon=AES.rcon, sbox=AES.sbox)
		return cipher

	@staticmethod
	def format_length(length, size):
		"""Give the hexadecimal notation of decimal length on size digits
			format_length(2, 4) = 0002
			format_length(16,3) = 010
		"""
		formatted = hex(int(length)).split('0x')[1]
		while len(formatted) < size:
			formatted = '0' + formatted
		return formatted
