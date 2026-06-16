import hashlib
import os
import logging
import hmac
import time
from constants import ProtocolConfig
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

PASSWORD = b"steganography"

def get_time_windows():
    current_window = int(time.time() // 15)
    return (current_window - 1, current_window, current_window + 1)

def generate_isn():
    """
    Generates an ISN that can be recognized using the PASSWORD and that is valid for a window of 30 seconds.
    Based on the current time and 16 random bits, it generates a MAC using the password. It uses the first 2 bytes of the MAC.
    NOTE! The purpose of the mac is not really integrity, but achieveing plausible deniability when the password is not known
    """
    random_16_bits = int.from_bytes(os.urandom(2), byteorder='big')
    random_bytes = random_16_bits.to_bytes(2, byteorder='big')

    current_window_bytes = get_time_windows()[2].to_bytes(4, byteorder='big')

    mac = hmac.new(key=PASSWORD, msg=random_bytes + current_window_bytes, digestmod=hashlib.sha256).digest()
    mac_int = int.from_bytes(mac[:2], byteorder='big')

    return (random_16_bits << 16) | mac_int

def isn_contains_key(isn):
    """
    Verifies if the last byte is the expected MAC the first 2 bytes + PASSWORD and that it still is valid (not expired).
    """
    received_16_bits = isn >> 16
    received_mac = isn & 0xFFFF

    message = received_16_bits.to_bytes(2, byteorder='big')

    for window in get_time_windows():
        window_bytes = window.to_bytes(4, byteorder='big')
        expected_mac_bytes = hmac.new(key=PASSWORD, msg=message + window_bytes, digestmod=hashlib.sha256).digest()
        expected_mac_int = int.from_bytes(expected_mac_bytes[:2], byteorder='big')
        
        if received_mac == expected_mac_int:
            return True
            
    return False

def generate_keystream_bits(tcp_layer, session_key):
    seq_bytes = tcp_layer.seq.to_bytes(4, byteorder='big')
    ack_bytes = tcp_layer.ack.to_bytes(4, byteorder='big')

    info = seq_bytes + ack_bytes

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=1,
        salt=None,
        info=info,
    )
    
    keystream_byte = hkdf.derive(session_key)[0]

    mask = (1 << ProtocolConfig.BITS_PER_PACKET) - 1

    return keystream_byte & mask

def derive_session_key(isn1, isn2):
    smallest_isn = min(isn1, isn2)
    largest_isn = max(isn1, isn2)
    
    info = smallest_isn.to_bytes(4, byteorder='big') + largest_isn.to_bytes(4, byteorder='big')
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=None,
        info=info,
    )
    
    return hkdf.derive(PASSWORD)

def bits_to_str(bits: int):
    return format(bits, f'0{ProtocolConfig.BITS_PER_PACKET}b')

def get_connection_id(ip_layer, tcp_layer):
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    sport = tcp_layer.sport
    dport = tcp_layer.dport

    if src_ip < dst_ip:
        return (src_ip, sport, dst_ip, dport)
    else:
        return (dst_ip, dport, src_ip, sport)
