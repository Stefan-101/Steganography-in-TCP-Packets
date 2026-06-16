import logging
import argparse
import sys
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from utils import *
from constants import NetworkConfig
from connection import Connection

secret_data = None
out_file = None
jitter_enabled = True
execute_commands = True
connections = {}

def handle_connection_teardown(tcp_layer, connection_id, sender_name):
    """
    Handles TCP connection termination (RST or FIN/ACK sequences)
    and removes the connection from tracking when finished.
    """
    if connection_id not in connections:
        return
        
    conn: Connection = connections[connection_id]
    
    if "R" in tcp_layer.flags:
        logging.info(f"RST detected on connection {connection_id}. Force closing.")
        conn.flush_jitter_buffer()
        del connections[connection_id]
    elif "F" in tcp_layer.flags:
        conn.fin_count += 1
        logging.debug(f"FIN detected from {sender_name}. Count: {conn.fin_count}")
    elif "A" in tcp_layer.flags and conn.fin_count >= 2:
        logging.info(f"Final ACK detected on connection {connection_id}. Cleaning up.")
        conn.flush_jitter_buffer()
        del connections[connection_id]

def handle_outgoing_packet(tcp_layer, connection_id):
    """
    Handles outgoing packets (Alice -> Bob). 
    Creates connection state on SYN, and translates sequence numbers
    while injecting bits into packets.
    """
    if "S" in tcp_layer.flags:
        global out_file
        global jitter_enabled
        global execute_commands
        connections[connection_id] = Connection.create_from_syn(
            tcp_layer,
            out_file=out_file,
            execute_commands=execute_commands,
            jitter_enabled=jitter_enabled,
        )
        return
        
    if connection_id in connections:
        conn: Connection = connections[connection_id]
        
        # Translate sequence numbers and inject bits
        conn.translate_seq(tcp_layer)
        conn.inject_next_bits(tcp_layer)

        # Check for connection teardown
        handle_connection_teardown(tcp_layer, connection_id, "Alice")

def handle_incoming_packet(tcp_layer, connection_id):
    """
    Handles incoming packets (Bob -> Alice).
    Extracts data from Bob, translates acknowledgements.
    """
    if connection_id not in connections:
        return
        
    conn: Connection = connections[connection_id]
    
    # Extract bits from Bob before we translate the ACK sequence!
    if "S" not in tcp_layer.flags:
        conn.extract_and_process_bit(tcp_layer)
    
    # Translate ACK
    conn.translate_ack(tcp_layer)
    
    # Verify Bob's ISN
    if tcp_layer.flags == "SA":
        if not isn_contains_key(tcp_layer.seq):
            logging.error("Expected Bob's SynAck to contain the password")
        else:
            logging.info("Bob's ISN response has been verified!")
            conn.establish_session_key(tcp_layer.seq)   # tcp_layer.seq = bob's isn

    # Check for connection teardown
    handle_connection_teardown(tcp_layer, connection_id, "Bob")

def process_packet(packet):
    scapy_pkt = IP(packet.get_payload())

    if scapy_pkt.haslayer(TCP):
        tcp_layer = scapy_pkt[TCP]
        connection_id = get_connection_id(scapy_pkt[IP], tcp_layer)
        
        if tcp_layer.dport == NetworkConfig.PORT:
            handle_outgoing_packet(tcp_layer, connection_id)
        elif tcp_layer.sport == NetworkConfig.PORT:
            handle_incoming_packet(tcp_layer, connection_id)

        # recalculate checksums
        del scapy_pkt[IP].chksum
        del scapy_pkt[TCP].chksum
        packet.set_payload(bytes(scapy_pkt))
            
    packet.accept()

def main():
    # arg parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=False, help="Optional: Path to file to send")
    parser.add_argument("-o", "--out", default="alice_recv.bin", help="Filepath to save received data")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port to monitor (default: 80)")
    parser.add_argument("-b", "--bpp", type=int, default=2, choices=range(1, 9), help="Bits Per Packet (must match Bob)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging")
    parser.add_argument("--no-jitter", action="store_true", help="Disable the jitter buffer (process packets in wire-arrival order)")
    parser.add_argument("--no-exec", action="store_true", help="Do not execute received frames as shell commands; just save them to disk")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    # logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%H:%M:%S')
    logging.basicConfig(level=log_level, format='%(asctime)s.%(msecs)03d %(levelname)s: %(message)s', datefmt='%H:%M:%S')
    logging.info("Alice started")

    global out_file
    global secret_data
    global jitter_enabled
    global execute_commands

    NetworkConfig.PORT = args.port
    ProtocolConfig.BITS_PER_PACKET = args.bpp
    out_file = args.out
    jitter_enabled = not args.no_jitter
    execute_commands = not args.no_exec
    logging.info(f"Jitter buffer: {'enabled' if jitter_enabled else 'disabled'}; execute_commands: {execute_commands}")
    
    output_path = os.path.join("received", args.out)
    logging.info(f"Configuration: Port={args.port}, BPP={args.bpp}, Output Path={output_path}")

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