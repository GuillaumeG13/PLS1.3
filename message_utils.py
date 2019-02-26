from constants import *

def get_bytes(message, index, number):
  byte_index = 2*(index)
  return message[byte_index:byte_index + 2*number]

def get_bytes_list(message, index, number):
  bytes_list = list()
  for i in range(number):
    bytes_list.append(get_bytes(message, index + i, 1))
  return bytes_list

def hexa_to_dec(string):
  return int(string, 16)

def get_record_type(message):
  return message[:2]

def get_handshake_message_type(message):
  return message[10:12]

def is_handshake(message):
  return get_record_type(message) == RECORD_TYPES.HANDSHAKE

def is_client_hello(message):
  return is_handshake(message) & get_handshake_message_type(message) == HANDSHAKE_MESSAGE_TYPES.CLIENT_HELLO

def get_message_type(message):
  test_functions = {
   MESSAGES.CLIENT_HELLO: is_client_hello,
  }
  for t, f in test_functions.items() :
    if f(message) :
      return t
