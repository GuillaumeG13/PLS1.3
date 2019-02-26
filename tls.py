from tls_socket import *
from math import floor



class TLS:
	def __init__(self, curve, serveur=True):
		self.curve = curve
		self.callback = None
		self.socket = SocketTLS(ip="127.0.0.1", port=1799, server=False, workers=5)

	def hello(self, params):

		random = params['random']
		version = params['version']
		session_id = params['session_id']
		cipher_suites = params['cipher_suites']
		compression_method = params['compression_method']
		extension_length = params['extension_length']

		data = version + random + session_id + cipher_suites + compression_method + extension_length
		size = int(len(data) / 2)

		handshake_header = params['handshake_header'] + TLS.format_length(size, 6)
		header = params['header'] + TLS.format_length(size + 4, 4) + handshake_header

		msg = header + data

		self.socket.update(msg)
		self.socket.send()

		return msg

	def initialize_connection(self):
		self.socket.initialize_connection()

	@staticmethod
	def format_length(length, size):
		formatted = hex(length).split('0x')[1]
		while len(formatted) < size:
			formatted = '0' + formatted
		return formatted
