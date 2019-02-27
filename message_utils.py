from constants import *
from aes_utils import *

def get_bytes(message, index, number):
  byte_index = 2*(index)
  return message[byte_index:byte_index + 2*number]

def get_bytes_list(message, index, number, grouping=1):
  bytes_list = list()
  for i in range(number):
    bytes_list.append(get_bytes(message, index + i, grouping))
  return bytes_list

def b_len(bytes_string):
  return int(len(bytes_string) / 2)

def hexa_to_dec(string):
  return int(string, 16)

def dec_to_hexa(number, bytes_count):
  hexa_string = hex(number)[2:]
  if len(hexa_string) < 2*bytes_count:
    return ''.join(['0' for i in range(2*bytes_count - len(hexa_string))]) + hexa_string
  else:
    return hexa_string

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
