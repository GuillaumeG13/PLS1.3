from Crypto.Cipher import AES

def aes_decrypt_from_hex_string(data, key, iv):
  data = bytes.fromhex(data)
  key = bytes.fromhex(key)
  iv = bytes.fromhex(iv)
  aes = AES.new(key, AES.MODE_CBC, iv)
  return aes.decrypt(data).hex()
