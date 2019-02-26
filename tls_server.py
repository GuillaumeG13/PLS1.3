from random_utils import get_random_bytes_hexa
from tls_socket import SocketTLS
from messages import *

class Session():
	def __init__(self, client_hello):
		self.id = get_random_bytes_hexa(32)
		self.client_hello = client_hello
	
	def set_server_random(self, server_random):
		self.server_random = server_random

class Server():
	def __init__(self, name):
		self.name = name
		self.certificate = self.get_certificate()
		self.sessions = dict()

	def log(self, message):
		print("server ["+ self.name +"]: " + message)

	def log_receiving(self, message):
		self.log("RECEIVED: \"" + message + "\"")
	
	def log_sending(self, message):
		self.log("SENT: \"" + message + "\"")

	def get_certificate(self):
		# TODO
		return "3082032130820209a0030201020208155a92adc2048f90300d06092a864886f70d01010b05003022310b300906035504061302555331133011060355040a130a4578616d706c65204341301e170d3138313030353031333831375a170d3139313030353031333831375a302b310b3009060355040613025553311c301a060355040313136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c4803606bae7476b089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc73e7024c0dbcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412da3765211e1f3dc776caa53376eca3aecbec3aab73b31d56cb6529c8098bcc9e02818e20bf7f8a03afd1704509ece79bd9f39f1ea69ec47972e830fb5ca95de95a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a04692595c1352f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f7a1fa05210d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11130fe2ee829e4d029dc91cdd6716dbb9061886edc1ba94210203010001a3523050300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030206082b06010505070301301f0603551d23041830168014894fde5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b05000382010100591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533eff3659084324c9e7a504079d39e0d42987ffe3ebdd09c1cf1d914455870b571dd19bdf1d24f8bb9a11fe80fd592ba0398cde11e2651e618ce598fa96e5372eef3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf209e667fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d744462a06b42c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3ae348ce0f34ab2fb9c618371312b191041641c237f11a5d65c844f0404849938712b959ed685bc5c5dd645ed19909473402926dcb40e3469a15941e8e2cca84bb6084636a0"

	def get_or_initialize_session(self, client_hello):
		# TODO: reuse existing session
		session = Session(client_hello)
		self.sessions[get_random_bytes_hexa(32)] = session

	def hello(self, message):
		self.log("Hello!")
		client_hello = ClientHello(message)
		self.get_or_initialize_session(client_hello)

		server_random = get_random_bytes_hexa(32)
		# TODO: use generated session ID
		session_id = "00"
		cipher_suite = client_hello.cipher_suites[0]
		compression_method = client_hello.compression_methods[0]
		



	def handshake(self):	
		self.log("Handshake!")
	
	def send_data(self):	
		self.log("Sending some data")

	def run(self, socket):
		data = socket.receive()
		message = data.decode()
		self.log_receiving(message)
		
		self.hello(message)

	def start(self):
		socket = SocketTLS(ip="127.0.0.1", port=1799, server=True, workers=5, callback=self.run)
		socket.initialize_connection()

server = Server("www.abc.com")
server.start()
