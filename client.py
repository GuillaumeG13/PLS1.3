from tls import *

def callback(tls_socket):
	return "callback client"

# socket = SocketTLS(ip="127.0.0.1", port=1799, server=False, callback=callback)
# socket.initialize_connection()
# socket.update("One two one two\n")
# send = socket.send()
# print("Client send : " + send)


tls = TLS(None)
# tls.initialize_connection()
hello_client_params = {
	'random': "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	'session_id': "20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
	'cipher_suites': "00021301",
	'compression_method': "0100",
}
tls.secret = "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624"
a = tls.application_key_generation()
print(a)

