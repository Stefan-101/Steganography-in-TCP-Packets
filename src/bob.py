import logging
import argparse
import sys
import os
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from utils import *
from constants import NetworkConfig
from connection import Connection

out_file = None
secret_data = None
mitigated = False
connections = {}

def handle_connection_teardown(tcp_layer, connection_id, sender_name):
    """
    Handles TCP connection termination (RST or FIN/ACK sequences)
    and removes the connection from tracking when finished.
    """
    if connection_id not in connections:
        return
        
    conn: Connection = connections[connection_id]
    if conn is None:
        return
    
    if "R" in tcp_layer.flags:
        logging.info(f"RST detected on connection {connection_id}. Force closing.")
        conn.flush_jitter_buffer()
        del connections[connection_id]
    elif "F" in tcp_layer.flags:
        conn.fin_count += 1
        logging.debug(f"FIN detected from {sender_name}. Count: {conn.fin_count}")
    elif "A" == tcp_layer.flags and conn.fin_count >= 2:
        logging.info(f"Final ACK detected on connection {connection_id}. Cleaning up.")
        conn.flush_jitter_buffer()
        del connections[connection_id]

def handle_incoming_packet(scapy_pkt, tcp_layer, connection_id):
    """
    Handles incoming packets (Alice -> Bob).
    Detects SYN packets with covert ISN, extracts data,
    and translates acknowledgements.
    """
    if tcp_layer.flags == "S":
        isn = tcp_layer.seq
        logging.debug(f"Intercepted SYN packet. ISN: {isn}")
        
        if isn_contains_key(isn):
            logging.info(f"Key detected in ISN from {scapy_pkt[IP].src}")
            connections[connection_id] = isn   # this just marks the connection
        else:
            logging.info(f"Normal ISN detected from {scapy_pkt[IP].src}")
        return

    if connection_id not in connections:
        return

    conn: Connection = connections[connection_id]
    if conn is not None:
        conn.extract_and_process_bit(tcp_layer)
        conn.translate_ack(tcp_layer)
        
        handle_connection_teardown(tcp_layer, connection_id, "Alice")

def handle_outgoing_packet(tcp_layer, connection_id):
    """
    Handles outgoing packets (Bob -> Alice).
    Creates connection state on SYN-ACK, translates sequence numbers,
    and injects data into packets.
    """
    if connection_id not in connections:
        return
        
    if "S" in tcp_layer.flags:
        global out_file
        global secret_data
        global mitigated

        conn = Connection.create_from_syn(tcp_layer, out_file=out_file, mitigated=mitigated)

        # the session key is established using the isn from alice stored earlier (connections[connection_id])
        # and the isn generated here by bob
        conn.establish_session_key(connections[connection_id])
        
        # Queue Bob's message
        if secret_data:
            conn.queue_message(secret_data)
            
        connections[connection_id] = conn
        return

    conn: Connection = connections[connection_id]
    if conn is not None:
        conn.translate_seq(tcp_layer)
        # Inject bits from Bob's side
        conn.inject_next_bits(tcp_layer)

    handle_connection_teardown(tcp_layer, connection_id, "Bob")

def process_packet(packet):
    scapy_pkt = IP(packet.get_payload())

    if scapy_pkt.haslayer(TCP):
        tcp_layer = scapy_pkt[TCP]
        connection_id = get_connection_id(scapy_pkt[IP], tcp_layer)
        
        if tcp_layer.dport == NetworkConfig.PORT:
            handle_incoming_packet(scapy_pkt, tcp_layer, connection_id)
        elif tcp_layer.sport == NetworkConfig.PORT:
            handle_outgoing_packet(tcp_layer, connection_id)

        del scapy_pkt[IP].chksum
        del scapy_pkt[TCP].chksum
        packet.set_payload(bytes(scapy_pkt))
             
    packet.accept()

def main():
    # arg parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=False, help="Optional: Path to file to send covertly to Alice WIP")
    parser.add_argument("-o", "--out", default="bob_recv.bin", help="Filepath to save received data (default: exfiltrated_loot.bin)")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port to monitor (default: 80)")
    parser.add_argument("-b", "--bpp", type=int, default=2, choices=range(1, 9), help="Bits Per Packet (must match Alice)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging")
    parser.add_argument("--mitigated", action="store_true", help="Enable clock-tick gating: only inject/extract when the TCP clock ticked")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    # logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%H:%M:%S')
    logging.basicConfig(level=log_level, format='%(asctime)s.%(msecs)03d %(levelname)s: %(message)s', datefmt='%H:%M:%S')
    logging.info("Bob started")

    global out_file
    global secret_data
    global mitigated

    NetworkConfig.PORT = args.port
    ProtocolConfig.BITS_PER_PACKET = args.bpp
    out_file = args.out
    mitigated = args.mitigated

    output_path = os.path.join("received", args.out)
    logging.info(f"Configuration: Port={args.port}, BPP={args.bpp}, Output Path={output_path}, mitigated={mitigated}")

    # load data to send
    if args.file:
        try:
            with open(args.file, "rb") as f:
                secret_data = f.read()
            logging.info(f"Loaded {len(secret_data)} bytes from {args.file} for transmission.")
        except FileNotFoundError:
            logging.error(f"Could not find file: {args.file}")
            sys.exit(1)

    # start packet processing
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logging.info("\nStopped.")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()