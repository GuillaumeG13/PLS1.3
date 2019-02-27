from random_utils import get_random_bytes_hexa
from tls_socket import SocketTLS
from messages import *
from message_utils import SERVER_CERTIFICATE_MESSAGE
from constants import PREDEFINED_SERVER_PUBLIC_KEY

class Session():
	def __init__(self, client_hello):
		self.id = get_random_bytes_hexa(32)
		self.client_hello = client_hello
		self.server_hello = None
		self.client_public_key = None
		self.server_private_key = None

		self.client_mac_key = None
		self.server_mac_key = None
		self.client_write_key = None
		self.server_write_key = None
		self.client_write_iv = None
		self.server_write_iv = None
	
	def set_server_hello(self, server_hello):
		self.server_hello = server_hello
	


class Server():
	def __init__(self, name):
		self.name = name
		self.sessions = dict()

	def log(self, message):
		print(">>> SERVER ["+ self.name +"]: " + message)

	def log_receiving(self, message):
		self.log("RECEIVED: \"" + message + "\"")
	
	def log_sending(self, message):
		self.log("SENT: \"" + message + "\"")

	def get_or_initialize_session(self, client_hello):
		# TODO: reuse existing session
		session = Session(client_hello)
		self.sessions[get_random_bytes_hexa(32)] = session
		return session

	def hello(self, socket, message):
		self.log("Someone is saying hello to me")
		client_hello = ClientHello(message)
		session = self.get_or_initialize_session(client_hello)

		server_hello = ServerHello(cipher_suites=client_hello.cipher_suites, compression_methods=client_hello.compression_methods)

		socket.update(server_hello.serialize())
		socket.send()
		# TODO: build server certificate message
		socket.update(SERVER_CERTIFICATE_MESSAGE)
		socket.send()

		session.server_private_key, session.server_public_key = self.key_exchange_generation()

		key_exchange = ServerKeyExchange(session.server_public_key)
		socket.update(key_exchange.serialize())
		self.log_sending(key_exchange.serialize())
		socket.send()
	
	def key_exchange_generation(self):
		return PREDEFINED_SERVER_RANDOM_PRIVATE_KEY, PREDEFINED_SERVER_PUBLIC_KEY
		
	def key_exchange(self):	
		self.log("Take my keys!")
	
	def send_data(self):	
		self.log("Sending some data")

	def run(self, socket):
		data = socket.receive()
		message = data.decode()
		self.log_receiving(message)
		get_message_type(message)

		self.hello(socket, message)

	def start(self):
		socket = SocketTLS(ip="127.0.0.1", port=1799, server=True, workers=5, callback=self.run)
		socket.initialize_connection()

server = Server("www.abc.com")
server.start()

