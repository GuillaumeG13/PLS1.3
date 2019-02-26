from constants import *
from crypto_utils import *

def get_bytes(message, index, number):
  byte_index = 2*(index)
  return message[byte_index:byte_index + 2*number]

def get_bytes_list(message, index, number, grouping=1):
  bytes_list = list()
  for i in range(number):
    bytes_list.append(get_bytes(message, index + i, grouping))
  return bytes_list

def hexa_to_dec(string):
  return int(string, 16)

def dec_to_hexa(number, bytes_count):
  hexa_string = hex(number)[2:]
  if len(hexa_string) < 2*bytes_count:
    return (bytes_count - len(hexa_string)) * "0" + hexa_string


def get_record_type(message):
  return message[:2]

def get_handshake_message_type(message):
  return message[10:12]

def is_handshake(message):
  return get_record_type(message) == RECORD_TYPES.HANDSHAKE.value

def is_client_hello(message, **kwargs):
  return is_handshake(message) & (get_handshake_message_type(message) == HANDSHAKE_MESSAGE_TYPES.CLIENT_HELLO.value)

def is_client_key_exchange(message, **kwargs):
  return is_handshake(message) & (get_handshake_message_type(message) == HANDSHAKE_MESSAGE_TYPES.CLIENT_KEY_EXCHANGE.value)

def is_client_cipher_spec(message, **kwargs):
  return get_record_type(message) == RECORD_TYPES.CHANGE_CIPHER_SPEC.value

def is_client_handshake_finished(message, client_write_key, **kwargs):
  data_len = hexa_to_dec(get_bytes(message, 3, 2))
  data = get_bytes(message, 21, data_len)
  hexiv = get_bytes(message, 5, 16)
  
  return is_handshake(message) & (get_bytes(aes_decrypt_from_hex_string(data, client_write_key, hexiv), 0, 1) == HANDSHAKE_MESSAGE_TYPES.FINISHED.value)

def get_message_type(message, **kwargs):
  test_functions = {
   MESSAGES.CLIENT_HELLO: is_client_hello,
   MESSAGES.CLIENT_KEY_EXCHANGE: is_client_key_exchange,
   MESSAGES.SERVER_HANDSHAKE_FINISHED: is_client_handshake_finished,
  }
  for t, f in test_functions.items() :
    if f(message, **kwargs) :
      return t


# message = "1603030040404142434445464748494a4b4c4d4e4f227bc9ba81ef30f2a8a78ff1df50844d5804b7eeb2e214c32b6892aca3db7b78077fdd90067c516bacb3ba90dedf720f"
# hexkey = "f656d037b173ef3e11169f27231a84b6"
# print(get_message_type(message, client_write_key=hexkey))