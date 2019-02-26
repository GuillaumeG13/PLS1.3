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
		self.server_random = get_random_bytes_hexa(32)
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
			message = RECORD_TYPES.HANDSHAKE.value + PROTOCOL_VERSION + 40 + 

			n_c_s = hexa_to_dec(get_bytes(message, 44, 2))
			n_c_m = hexa_to_dec(get_bytes(message, 44 + 2 + n_c_s, 1))
      
			self.client_random = get_bytes(message, 11, 32)
			self.cipher_suites = get_bytes_list(message, 46, n_c_s)
			self.compression_methods = get_bytes_list(message, 46 + n_c_s + 1, n_c_m)
      

