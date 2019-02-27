from random_utils import *
from message_utils import *

class ClientHello():
  # TODO: make it to work both ways: for sezializing and for parsing
	def __init__(self, message):
		if not is_client_hello(message):
			raise Exception("Incorrect message: This is not a client hello.")
			
		else:
			""" 
			Record Header: 5 bytes
			Handshake Header: 4 bytes
			Client Version: 2 bytes
			Client Random: 32 bytes
			Session ID: 2 bytes
				--> 45 bytes
			Cipher Suites length: 2 bytes
			Compression Methods length: 1 byte
			"""
			n_c_s = hexa_to_dec(get_bytes(message, 44, 2))
			n_c_m = hexa_to_dec(get_bytes(message, 44 + 2 + n_c_s, 1))
      
			self.client_random = get_bytes(message, 11, 32)
			self.cipher_suites = get_bytes_list(message, 46, n_c_s, 2)
			self.compression_methods = get_bytes_list(message, 46 + n_c_s + 1, n_c_m)

class ServerHello():
  # TODO: make it to work both ways: for sezializing and for parsing
	def __init__(self, **kwargs):
		# self.server_random = get_random_bytes_hexa(32)
		self.server_random = PREDEFINED_SERVER_RANDOM
		# TODO: get session_id from created session
		self.session_id = "00"
		self.cipher_suite = kwargs.get("cipher_suites")[0]
		self.compression_method = kwargs.get("compression_methods")[0]

	def serialize(self):
			""" 
			Record Header: 5 bytes
			Handshake Header: 4 bytes
			Server Version: 2 bytes
			Server Random: 32 bytes
			Session ID: 1 bytes -- None
			Cipher Suite: 2 bytes
			Compression Method: 1 byte
			"""
			n_bytes_handshake = dec_to_hexa(49, 2)
			n_bytes_hello_data = dec_to_hexa(45, 3)
			record_header = RECORD_TYPES.HANDSHAKE.value + PROTOCOL_VERSION + n_bytes_handshake
			handshake_header = HANDSHAKE_MESSAGE_TYPES.SERVER_HELLO.value + n_bytes_hello_data
			extensions = "0005ff01000100"

			message =  record_header + handshake_header + SERVER_VERSION + self.server_random + self.session_id + self.cipher_suite + self.compression_method + extensions

			return message

class ServerKeyExchange():
	def __init__(self, public_key):
		self.public_key = public_key

	def serialize(self):
		""" 
		Record Header: 5 bytes
		Handshake Header: 4 bytes
		Curve Info: 2 bytes
		Public Key Length: 1 byte
		Public Key: 32 byte
		Signature: 260 bytes
		"""
		n_bytes_handshake = dec_to_hexa(300, 2)
		n_bytes_key_exchange = dec_to_hexa(296, 3)
		n_bytes_public_key = dec_to_hexa(32, 1)

		record_header = RECORD_TYPES.HANDSHAKE.value + PROTOCOL_VERSION + n_bytes_handshake
		handshake_header = HANDSHAKE_MESSAGE_TYPES.SERVER_KEY_EXCHANGE.value + n_bytes_key_exchange

		curve_info = "03001d"

		signature = PREDEFINED_SIGNATURE

		message = record_header + handshake_header + curve_info + n_bytes_public_key + self.public_key + signature
		
		return message
