from enum import Enum

class RECORD_TYPES(Enum):
  HANDSHAKE = "16"
  CHANGE_CIPHER_SPEC = "14"
  APPLICATION_DATA = "17"
  ALERT = "15"

class HANDSHAKE_MESSAGE_TYPES(Enum):
  CLIENT_HELLO = "01"
  SERVER_HELLO = "02"
  CERTIFICATE = "0b"
  SERVER_KEY_EXCHANGE = "0c"
  SERVER_HELLO_DONE = "0e"
  CLIENT_KEY_EXCHANGE = "10"
  FINISHED = "14"

class COMPRESSION_METHODS(Enum):
  NO_COMPRESSION = "00"

class MESSAGES(Enum):
  CLIENT_HELLO = 0,
  SERVER_HELLO = 1,
  SERVER_CERTIFICATE = 2,
  SERVER_KEY_EXCHANGE = 3,
  SERVER_HELLO_DONE = 4,
  CLIENT_KEY_EXCHANGE = 5,
  CLIENT_CHANGE_CIPHER_SPEC = 6,
  CLIENT_HANDSHAKE_FINISHED = 7,
  SERVER_CHANGE_CIPHER_SPEC = 8,
  SERVER_HANDSHAKE_FINISHED = 9,
  CLIENT_APPLICATION_DATA = 10,
  SERVER_APPLICATION_DATA = 11,
  CLIENT_CLOSE_NOTIFY = 12,

PROTOCOL_VERSION = "0303"
SERVER_VERSION = "0303"
