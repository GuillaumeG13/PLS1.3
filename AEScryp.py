from AEScryp_matrix import *


class AES:
	plaintext = []     # Plaintext : will contain data after each encryption step
	round_key = []
	round     = 0
	#iv		  = []

	def __init__(self, plaintext = "Resto en ville ?", key = [[0x2b,0x28,0xab,0x09],[0x7e,0xae,0xf7,0xcf],[0x15,0xd2,0x15,0x4f],[0x16,0xa6,0x88,0x3c]]):
		try:
			self.plaintext = MatrixHexa(plaintext)
			self.round_key = [MatrixHexa(key)]
			#self.iv 	   = MatrixHexa(iv)
			#self.memory    = MatrixHexa(plaintext)
		except TypeError:
			raise TypeError("Plaintext and key shall be a string or a matrix")

	def __str__(self):
		return "Plaintext : \n" + format(self.plaintext) + "\n"

	def shift(self):
		for i in range(len(self.plaintext)):
			self.plaintext[i].shift(i)

	def shift_inv(self):
		for i in range(len(self.plaintext)):
			self.plaintext[i].shift_inv(i)

	def sub_bytes(self, sbox):
		for i in range(len(self.plaintext)):
			self.plaintext[i].sub_bytes(sbox)

	def sub_bytes_inv(self, sbox_inv):
		for i in range(len(self.plaintext)):
			self.plaintext[i].sub_bytes(sbox_inv)

	def mix_columns(self, galois):
		for i in range(len(self.plaintext)):
			col = RowHexa(self.plaintext.get_column_as_list(i))
			col.mix_columns(galois)
			self.plaintext.set_column(i, col)

	def mix_columns_inv(self, galois_inv):
		for i in range(len(self.plaintext)):
			col = RowHexa(self.plaintext.get_column_as_list(i))
			col.mix_columns(galois_inv)
			self.plaintext.set_column(i, col)

	def key_expander(self, rcon=MatrixHexa(), sbox=[]):
		for round in range(1, 11):
			old_key = self.round_key[round - 1]
			computed_key = MatrixHexa()
			for i in range(4):
				if i % 4 == 0:
					tmp = RowHexa(old_key.get_column_as_list(len(old_key) - 1))
					tmp.shift()
					tmp.sub_bytes(sbox)
					tmp += RowHexa(rcon.get_column_as_list(round - 1))
				else:
					tmp = RowHexa(computed_key.get_column_as_list(i - 1))
				computed_key.set_column(i, tmp + RowHexa(old_key.get_column_as_list(i)))
			self.round_key.append(computed_key)

	def add_round_key(self):
		self.plaintext += self.round_key[self.round]

	def add_round_key_inv(self):
		self.plaintext += self.round_key[10 - self.round]

	def encrypt(self, galois, rcon, sbox):
		self.key_expander(rcon=rcon, sbox=sbox)
		self.round = 0
		#self.plaintext += self.iv
		self.add_round_key()
		self.round += 1

		while self.round < 10:
			#self.plaintext += self.memory
			self.sub_bytes(sbox)
			self.shift()
			self.mix_columns(galois)
			self.add_round_key()
			self.round += 1

		#self.plaintext += self.memory
		self.sub_bytes(sbox)
		self.shift()
		self.add_round_key()
		self.round += 1

		cypher = ""
		for row in self.plaintext.content:
			cypher += " ".join((format(hex(hexa)) for hexa in row)) + " "
		return cypher

	def decrypt(self, galois_inv, rcon, sbox_inv, sbox):
		self.key_expander(rcon=rcon, sbox=sbox)
		self.round = 0
		self.add_round_key_inv()
		#self.plaintext += self.iv
		self.round += 1

		while self.round < 10:
			self.shift_inv()
			self.sub_bytes_inv(sbox_inv)
			self.add_round_key_inv()
			self.mix_columns_inv(galois_inv)
			#self.plaintext += self.memory
			self.round += 1

		self.shift_inv()
		self.sub_bytes_inv(sbox_inv)
		self.add_round_key_inv()
		#self.plaintext += self.memory
		self.round += 1

		cypher = ""
		for row in self.plaintext.content:
			cypher += " ".join((format(hex(hexa)) for hexa in row)) + " "
		return cypher



#aes = AES()
#print(aes)
#cypher = aes.encrypt(galois=galois, rcon=rcon, sbox=sbox)
#cypher = aes.decrypt(galois_inv=galois_inv, rcon=rcon, sbox_inv=sbox_inv, sbox=sbox)
#print(cypher)


'''
from AEScryp.py import *

def data_encryption(self, data, key)
	aes = AES(data, key)
	cypher = aes.encrypt(galois=galois, rcon=rcon, sbox=sbox)
	self.socket.data = cypher
	self.socket.update(cypher)
	self.socket.send()

def data_decryption(self, data, key)
	aes = AES(data, key)
	plaintext = aes.decrypt(galois_inv=galois_inv, rcon=rcon, sbox_inv=sbox_inv, sbox=sbox)
	self.socket.data = plaintext
	self.socket.update(plaintext)
	self.socket.send()
'''