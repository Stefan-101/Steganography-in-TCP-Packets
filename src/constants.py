class NetworkConfig:
    # used for local docker environment
    ALICE_IP = "172.7.0.2"
    BOB_IP = "172.8.0.3"

    # used for testing on the internet
    PORT = 80


class ProtocolConfig:
    SOF = "11100010010"
    LENGTH_BITS_PREFIX = 16
    MAX_PAYLOAD_BYTES = (2 ** LENGTH_BITS_PREFIX) - 1
    BITS_PER_PACKET = 2         # should be <= 8 because the keystream generator uses just one byte


class ConnectionState:
    WAITING_SOF = "WAITING_SOF"
    READING_LENGTH = "READING_LENGTH"
    READING_PAYLOAD = "READING_PAYLOAD"