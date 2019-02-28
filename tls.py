from tls_socket import *
import subprocess
import hashlib
from binascii import unhexlify
from constants import *
from message_utils import *
import hmac
import AEScryp as AES

DEBUG = True

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
		self.log("Starting...")
		if self.serveur:
			self.socket.callback = self.run_as_serveur
			self.initialize_connection()
		else:
			self.run_as_client()

	def run_as_client(self):
		self.log("Running as client")
		self.initialize_connection()
		self.generate_asymetrique_keys()
		params = {
			'random': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
			'session_id': 'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
		}
		
		self.log_title("SENDING A CLIENT HELLO")
		self.hello(params)

		self.log_title("WAITING FOR A SERVER HELLO")
		self.receive_hello()
		self.handshake_key_generation()

		self.log_title("WAITING FOR SERVER CERTIFICATE")
		self.verify_certificates()
		print(self.messageHandshake)
		print(self.application_key_generation())

		self.log_title("SENDING CLIENT HANDSHAKE FINISHED")
		self.send_client_handshake_finished()

	def run_as_serveur(self, sock):
		self.log("Running as server")
		self.generate_asymetrique_keys()

		self.log_title("WAITING FOR A CLIENT HELLO")
		self.receive_hello()
		params = {
			'random': '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
			'session_id': 'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
		}
		
		self.log_title("SENDING A SERVER HELLO")
		self.hello(params)
		print(self.messageHelloList)
		self.handshake_key_generation()
		params = {
			'request_context': '00',
		}
		self.log_title("SENDING CERTIFICATE")
		self.send_certificate(params)
		print(self.application_key_generation())

		self.log_title("WAITING FOR CLIENT HANDSHAKE FINISHED")
		self.receive_client_handshake_finished()
		# Receive client handshake finished


	def initialize_connection(self):
		self.socket.initialize_connection()

	def get_extension_key_share(self):
		"""
		00 33 - assigned value for extension "Key Share"
		00 20 - 0x20 (32) bytes of public key follows
		9f d7 ... b6 15 - public key from the step "Exchange Generation"
		"""
		return EXTENSIONS.KEY_SHARE.value + dec_to_hexa(b_len(self.public_key), 2) + self.public_key


	# Tested
	def hello(self, params):
		self.log("Sending Hello")
		"""
		Tested for server part
		:param params:
		:return:
		"""
		random = params['random']
		session_id = params['session_id']

		key_share_extension = self.get_extension_key_share()
		extension_length = dec_to_hexa(b_len(key_share_extension), 2)
		session_id_length = dec_to_hexa(b_len(session_id), 1)

		data = SERVER_CLIENT_VERSION + random + session_id_length + session_id + extension_length + key_share_extension
		
		data_length = self.format_length(len(data)/2, 6)
		print(data_length)

		handshake_header = HANDSHAKE_MESSAGE_TYPES.SERVER_HELLO.value if self.serveur else HANDSHAKE_MESSAGE_TYPES.CLIENT_HELLO.value
		handshake_header += data_length

		handshake_length = self.format_length(len(handshake_header + data)/2, 4)
		record_header = RECORD_TYPES.HANDSHAKE.value + (TLS12_PROTOCOL_VERSION if self.serveur else TLS11_PROTOCOL_VERSION) + handshake_length

		msg = record_header + handshake_header + data

		self.log("Hello record_header : " + format_bytes(record_header))
		self.log("Hello handshake_header : " + format_bytes(handshake_header))
		self.log("Hello key_share_extension : " + format_bytes(key_share_extension))

		self.socket.update(msg)
		self.socket.send()

		self.messageHelloList.append(msg[10:])
		self.messageHandshake.append(msg[10:])

		return data

	# Tested
	def receive_hello(self):
		message = self.socket.receive().decode()
		self.log("Received message: " + message)
		self.messageHelloList.append(get_bytes(message, 5))
		self.messageHandshake.append(get_bytes(message, 5))
		""" 
		Record Header: 5 bytes
		Handshake Header: 4 bytes
		Client Version: 2 bytes
		Client Random: 32 bytes
			--> 43 bytes
		Session ID length: 1 byte
		"""
		random_index = 5 + 4 + 2

		session_id_index = random_index + 32
		n_session_id = hexa_to_dec(get_bytes(message, session_id_index, 1))

		extensions_index = session_id_index + 1 + n_session_id

		# if extension_type != EXTENSIONS.KEY_SHARE.value :
		# 	raise Exception('There should be only one extension in Hello: Key Share ("00 33")')

		"""
		Extensions Length: 2 bytes
		Extension Type: 2 bytes
		Extension Length: 2 bytes
		"""
		key_share_index = extensions_index + 2 
		n_key_share = hexa_to_dec(get_bytes(message, key_share_index, 2))

		hello = dict()
		hello['random'] = get_bytes(message, random_index, 32)
		hello['session_id'] = get_bytes(message, session_id_index + 1, n_session_id)
		hello['public_key'] = get_bytes(message, key_share_index + 4, n_key_share)
		self.external_key = hello['public_key']
		self.log("Received public key = " + self.external_key)

		return hello

	def generate_asymetrique_keys(self):
		# TODO : Maxime & Marcou
		if not self.serveur:
			self.private_key = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
			self.public_key = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
		else:
			self.private_key = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
			self.public_key = "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615"
		self.log("Public key = " + self.public_key)
		self.log("Private key = " + self.private_key)

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
		# hello_hash = hashlib.sha256(unhexlify("".join(self.messageHelloList))).hexdigest()

		hello_hash = "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5"
		self.log("Hello hash : " + hello_hash)
		self.key_expansion(hello_hash)
		return self.client_handshake_key.hex(), self.server_handshake_key.hex(), self.client_handshake_iv.hex(), self.server_handshake_iv.hex()

	# Tested
	def send_certificate(self, params):
		self.log("Sending centificate...")
		# First message is related to certificate
		"""
			[DATA VERIFY]:
		Handshake message type (0f): 1 byte
		Length of following: 3 bytes
		Data verify (SHA256 of DATA): 256 bytes
		Server Handshake Finished: ??? bytes

			[DATA]:
		Handshake message type (0b): 1 byte
		Length of following: 3 bytes
		Certificate Length: 3 bytes
		Certificate: 305 bytes
		Certificate extension: 2 bytes

			[SERVER HANDSHAKE FINISHED]
		Server Handshake Finished (14): 1 byte
		Length of following: 3 bytes
		Verify Data: HMAC of finished_key and finished_hash: ??? bytes
		"""

		data = self.format_length(len(self.certificate) / 2, 6) + self.certificate + CERTIFICATE_EXTENSION
		data = REQUEST_CONTEXT + self.format_length(len(data)/2, 6) + data
		data = HANDSHAKE_MESSAGE_TYPES.CERTIFICATE.value + self.format_length(len(data) / 2, 6) + data

		# This message contain information to verify certificate information
		data_verify = hashlib.sha256(str.encode(data)).hexdigest()
		# TODO : Signature with elliptical curve
		# data = self.curve.sign(data)
		data_verify += HANDSHAKE_MESSAGE_TYPES.CERTIFICATE_VERIFY.value + self.format_length(len(data)/2, 6) + data_verify + self.send_server_handshake_finished()

		# data = self.data_encryption(data + data_verify, self.server_handshake_key, self.server_handshake_iv)
		data += data_verify
		header = RECORD_TYPES.APPLICATION_DATA.value + TLS12_PROTOCOL_VERSION + self.format_length(len(data)/2, 4) # Add data size verification data < 16^5 - 1
		data = header + data
		self.log("Wrapper data : " + data)
		self.socket.update(data)
		self.socket.send()
		self.log("Certificate sent!")
		# self.messageHandshake.append(data) # Wrapper is not an handshake

	def verify_certificates(self):
		self.log("Waiting for certificate...")
		data = self.socket.receive().decode()
		self.log("Certificate received!")
		self.log("Received: " + format_bytes(data))

		record_type = get_bytes(data, 0, 2)
		self.log("type = " + record_type)

		cipher = get_bytes(data, 5)
		body = cipher
		# body = self.decrypt(cipher, self.server_handshake_key, self.server_handshake_iv)

		self.log("BODY = " + format_bytes(body))
		certificate_type = get_bytes(body, 0, 2)
		certificate_size = hexa_to_dec(get_bytes(body, 8, 3))
		self.log("certificate_size = " + format(certificate_size))

		certificate = get_bytes(body, 11, certificate_size)
		self.log("certificate = " + format_bytes(certificate))
		# TODO : Verify the content of the certificate

		index = 22 + 2 * certificate_size

		verify_size = int(body[index+6:index+12],16)
		verify = body[index+12: index+12+verify_size]
		
		self.log("verify = " + format_bytes(verify))
		
		# TODO : Verify Signature

		# index = index+12+verify_size
		# finish_size = int(body[index+2:index+6],16)
		# finish = body[index+6:index+6+finish_size]
		finish = ""
		self.log("finish =  " + format(finish))

		self.receive_server_handshake_finished(finish)

	def send_client_handshake_finished(self):
		finished_key = self.hkdf_expand_label(self.client_handshake_traffic_secret, b"finished", b"", 32)
		finished_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
		verify_data = hmac.new(finished_key, finished_hash).hexdigest()
		# data = self.data_encryption(verify_data, self.client_handshake_key, self.client_handshake_iv)
		data = verify_data
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

		self.log("Challenge Frame : " + data)
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
			# if verify_data != hmac.new(finished_key, finished_hash).hexdigest():
			#	raise ValueError("Verify data mismatch")
			self.log('Receive client handshake')
	# Tested
	def receive_server_handshake_finished(self, finish):
		finished_key = self.hkdf_expand_label(self.server_handshake_traffic_secret, b"finished", b"", 32)
		finished_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
		verify_data = hmac.new(finished_key, finished_hash).digest()

		# if finish != verify_data:
		#	raise ValueError('Challenge failed')
		print('Receive server handshake')
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
		handshake_hash = hashlib.sha256(unhexlify("".join(self.messageHandshake))).digest()
		# handshake_hash = unhexlify("22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b")
		return self.key_expansion_application(handshake_hash)

	def log(self, message):
		if DEBUG == True:
			header = ' [SERVER]: ' if self.serveur else ' [CLIENT]: '
			print(header, end="")
			print(message)

	def log_title(self, title):
		print("\n\t\t-- " + title + " --")

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
