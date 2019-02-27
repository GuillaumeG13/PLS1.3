import random as random

def get_random_bytes_hexa(number_of_bytes):
  chars = "0123456789abcdef"
  string = ""
  for i in range(number_of_bytes):
    a = random.randint(0, 15)
    b = random.randint(0, 15)
    string += chars[a] + chars[b] 
  return string
