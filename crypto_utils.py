from Crypto.Cipher import AES

def aes_decrypt_from_hex_string(data, key, iv):
  data = bytes.fromhex(data)
  key = bytes.fromhex(key)
  iv = bytes.fromhex(iv)
  aes = AES.new(key, AES.MODE_CBC, iv)
  return aes.decrypt(data).hex()

# data = "227bc9ba81ef30f2a8a78ff1df50844d5804b7eeb2e214c32b6892aca3db7b78077fdd90067c516bacb3ba90dedf720f"
# key = "f656d037b173ef3e11169f27231a84b6"
# iv = "404142434445464748494a4b4c4d4e4f"

# print(aes_decrypt_from_hex_string(data, key, iv))