from message_utils import *

class ClientHello():
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
			self.client_random = get_bytes(message, 11, 32)
			n_c_s = hexa_to_dec(get_bytes(message, 44, 2))
			n_c_m = hexa_to_dec(get_bytes(message, 44 + 2 + n_c_s, 1))
			self.cipher_suites = get_bytes_list(message, 46, n_c_s)
			self.compression_methods = get_bytes_list(message, 46 + n_c_s + 1, n_c_m)