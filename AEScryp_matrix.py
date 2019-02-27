class RowHexa:
	content = []

	def __init__(self, content):
		if isinstance(content, str):
			# the content is given as a string
			self.content = [0] * len(content)
			for i in range(len(content)):
				self[i] = ord(content[i])
		elif isinstance(content, list) and len(content) > 0 and isinstance(content[0], int):
			# the content is given as a list of integer
			self.content = [0] * len(content)
			for i in range(len(content)):
				self[i] = content[i]
		elif isinstance(content, RowHexa):
			self.content = list(content.content)

		else:
			raise TypeError('The content used to initialize the RowHexa object shall be a string or a list of integer or a RowHexa object')

	def __str__(self):
		tmp = ''
		for i in range(len(self)):
			tmp += format(hex(self[i])) + ' '
		return tmp

	"""
	def __str__(self):
		tmp = '['
		for i in range(len(self.content)):
			tmp += format(hex(self.content[i])) + ','
		return tmp + ']'
	"""

	def __getitem__(self, item):
		"""
		Define the addition as a XOR element by element
		"""
		return self.content[item]

	def __setitem__(self, key, value):
		if isinstance(value, int) and isinstance(key, int):
			self.content[key] = value
		else:
			raise TypeError('Key and Value have to be integers')

	def __iadd__(self, other):
		return self + other

	def __add__(self, other):
		if isinstance(other, RowHexa) and len(other) == len(self):
			new = RowHexa(list((self[i] ^ other[i] for i in range(len(self)))))
			return new
		else:
			raise TypeError('The value have to be a RowHexa with the same size')

	def __len__(self):
		return len(self.content)

	def __eq__(self, other):
		if len(self) != len(other):
			return False
		for i in range(len(self)):
			if self[i] != other[i]:
				return False
		return True

	def reset(self):
		self.content = [0] * len(self)

	def unit_shift(self):
		"""
		Make a shift of 1 index to the left
		"""
		memory = self[0]
		for i in range(1, len(self)):
			self[i - 1] = self[i]
		self[len(self) - 1] = memory

	def shift(self, inc=1):
		"""
		Make a shift of inc index to the left
		:param inc: number of shift shall be done
		"""
		for i in range(inc):
			self.unit_shift()

	def sub_bytes(self, sbox):
		"""
		Apply the linear transformation given by the sbox
		:param sbox: list of 256 values
		"""
		for i in range(len(self)):
			self[i] = sbox[self[i]]

	@staticmethod
	def multiplication_galois(a, b):
		"""
		Perform the multiplication a*b in the galois space
		:param a: (int < 4)
		:param b: (hex 16bits)
		:return: (hex 16bits) result of the multiplication
		"""
		if a < 2:
			return b
		elif a == 2:
			return b << 1 ^ int(bin(b)[2:][0] and (len(bin(b)[2:]) < 8)) * 283
		else:
			return RowHexa.multiplication_galois(2, b) ^ RowHexa.multiplication_galois(1, b)

	def mix_columns(self, galois):
		"""
		Calculate the matrix product of the GALOIS matrix and the current state
		:return:
		"""
		tmp = RowHexa(self)
		self.reset()
		for i in range(len(self)):
			for j in range(len(self)):
				self[i] ^= RowHexa.multiplication_galois(galois[i][j], tmp[j])


class MatrixHexa:
	content = []

	def __init__(self, content=None, size=4):
		self.content = [0] * size

		if content is None:
			self.content = list((RowHexa([0x0]*size) for i in range(size)))

		elif isinstance(content, str):
			tmp = [""] * size
			for i in range(len(content)):
				tmp[i % size] += content[i]
			for i in range(len(tmp)):
				self[i] = RowHexa(tmp[i])

		elif isinstance(content, list) and len(content) > 0 and isinstance(content[0], list) and len(content[0]) > 0 and isinstance(content[0][0], int):
			self.content = list((RowHexa(content[i]) for i in range(len(content))))
		else:
			raise TypeError('The content used to initialize the MatrixHexa object shall be a string or a list of integer or a None object')

	def __str__(self):
		tmp = ''
		for i in range(len(self)):
			tmp += 'Ligne' + format(i) + ' : ' + format(self[i]) + '\n'
		return tmp

	"""
	def __str__(self):
		tmp = '['
		for i in range(len(self.content)):
			tmp += format(self.content[i]) + ','
		return tmp +  ']'
	"""

	def __getitem__(self, item):
		return self.content[item]

	def __setitem__(self, key, value):
		self.content[key] = value

	def __len__(self):
		return len(self.content)

	def __eq__(self, other):
		if len(self) != len(other):
			return False
		for i in range(len(self)):
			if not (self[i] == other[i]):
				return False
		return True

	def __iadd__(self, other):
		return self + other

	def __add__(self, other):
		if isinstance(other, MatrixHexa) and len(other) == len(self) and len(other[0]) == len(self[0]):
			new = MatrixHexa()
			for i in range(len(self)):
				new[i] = self[i] + other[i]
			return new
		else:
			raise TypeError('The value have to be a MatrixHexa with the same size')

	def get_column_as_list(self, index):
		"""
		Get a column in the matrix
		:param index: index of the column
		:return: list
		"""
		tmp = []
		for k in range(len(self)):
			tmp.append(self[k][index])
		return tmp

	def set_column(self, index, column):
		"""
		Set the column in the matrix at the index i
		:param index: column index
		:param column: new column values given as list or RowHexa object
		"""
		if len(column) == len(self[0]):
			for k in range(len(self)):
				self[k][index] = column[k]
		else:
			raise ValueError('The column set have to get the same size than the matrix')

sbox = [
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

galois = [
	[2, 3, 1, 1],
	[1, 2, 3, 1],
	[1, 1, 2, 3],
	[3, 1, 1, 2]
]

rcon = MatrixHexa([
	[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
	[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
	[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
	[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
])