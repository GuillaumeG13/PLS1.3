from aes_matrix import *


class AES:
	plaintext = []     # Plaintext : will contain data after each encryption step
	round_key = []
	round     = 0

	def __init__(self, plaintext="Resto en ville ?", key="+~(®Ò¦«÷	ÏO<"):
		try:
			self.plaintext = MatrixHexa(plaintext)
			self.round_key = [MatrixHexa(key)]
		except TypeError:
			raise TypeError("Plaintext and key shall be a string or a matrix")

	def __str__(self):
		return "Plaintext : \n" + format(self.plaintext) + "\n"

	def shift(self):
		for i in range(len(self.plaintext)):
			self.plaintext[i].shift(i)

	def sub_bytes(self, sbox):
		for i in range(len(self.plaintext)):
			self.plaintext[i].sub_bytes(sbox)

	def mix_columns(self, galois):
		for i in range(len(self.plaintext)):
			col = RowHexa(self.plaintext.get_column_as_list(i))
			col.mix_columns(galois)
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

	def encrypt(self, galois, rcon, sbox):
		self.key_expander(rcon=rcon, sbox=sbox)
		self.round = 0
		self.add_round_key()
		self.round += 1

		while self.round < 10:
			self.sub_bytes(sbox)
			self.shift()
			self.mix_columns(galois)
			self.add_round_key()
			self.round += 1
		self.sub_bytes(sbox)
		self.shift()
		self.add_round_key()
		self.round += 1

		cypher = ""
		for row in self.plaintext.content:
			cypher += " ".join((format(hex(hexa)) for hexa in row)) + " "
		return cypher


aes = AES()
print(aes)
cypher = aes.encrypt(galois=galois, rcon=rcon, sbox=sbox)
print(cypher)
