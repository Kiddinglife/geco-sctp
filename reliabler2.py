import ctypes
from time import sleep
from _struct import unpack_from
from _struct import pack_into
import struct
from copy import deepcopy
import binascii
import cPickle as pickle
import logging
from random import random, Random, randint
from _ast import Pass
# logging.basicConfig(level=logging.DEBUG,
#                 format='[line:%(lineno)d] %(levelname)s %(message)s',
#                 datefmt='%a, %d %b %Y %H:%M:%S',
#                 filename='myapp.log',
#                 filemode='w')
logging.basicConfig(level=logging.DEBUG,
                format='[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S')

'''
@note: 7 April fixup struct pack error; TSN should be assigned to each packet instead of each data chunk
@remeber_myself_why_assign_each_chunk_data_a_individual_tsn_for_IP_based_implementation?
1. build on UDP, you can receive a complete datagram from recvfrom(), packet bounary is obvious
so you can assign a unique tsn to a complete packet and each of carried user-data-chunks in it shared the same tsn
2. build on IP layer, packet bounary is anbious, in other words, what you receive from IP layer is blocks of bytes and 
there is no way to distiguse the user-data-chunk fragments bonary. So, we have to assign tsn to each of user-data-chunk
the core algo to reaasemble fragments is sequencial numbers assigned to each fragments just like puzzling games !

# 拼接内存快
# 方法一：快
# recvbuf = ctypes.create_string_buffer(len(bytedata) + 4) # this is more efficiently way because you only need allocate one mmeory
# pack_into("!6s16s",recvbuf,0, p1,p2)
# 方法二　slow and many memory frgments because 
# recvbuf = p1+p2 
# 方法三　等同于方法一 非常快　推荐使用。
# recvbuf = ''.join((p1, p2)) 
#ret = unpack_from("!I%ds" % len(bytedata), recvbuf, 0)
'''

# constants
MAX_PACKET_SIZE = 60  # 1500 - 20 - 8 # IP header 20 bytes plus UDP header 8 bytes

PACKET_HR_FORMATE = '!2I'
PACKET_HR_SIZE = 8

CHUNK_COMM_HDR_FORMATE = '!BH'
CHUNK_COMM_HDR_SIZE = 3  

O_DATA_CHUNK_COMM_HDR_FORMATE = '!I2HI'
O_DATA_CHUNK_COMM_HDR_SIZE = 12
# '!BH + I2HI + %ds'
O_FULL_DATA_CHUNK_FORMATE = CHUNK_COMM_HDR_FORMATE + O_DATA_CHUNK_COMM_HDR_FORMATE[1:] + '%ds'
O_DATA_CHUNK_FULL_HR_SIZE = CHUNK_COMM_HDR_SIZE + O_DATA_CHUNK_COMM_HDR_SIZE  # 

U_DATA_CHUNK_COMM_HDR_FORMATE = '!IHI'
U_DATA_CHUNK_COMM_HDR_SIZE = 10
# '!BH + IHI + %ds'
U_FULL_DATA_CHUNK_FORMATE = CHUNK_COMM_HDR_FORMATE + U_DATA_CHUNK_COMM_HDR_FORMATE[1:] + '%ds'
U_DATA_CHUNK_FULL_HR_SIZE = CHUNK_COMM_HDR_SIZE + U_DATA_CHUNK_COMM_HDR_SIZE

FULL_PACKET_O_DATA_CHUNK_FORMATE = PACKET_HR_FORMATE + O_FULL_DATA_CHUNK_FORMATE[1:]
FULL_PACKET_U_DATA_CHUNK_FORMATE = PACKET_HR_FORMATE + U_FULL_DATA_CHUNK_FORMATE[1:]

MAX_O_DATA_CHUNK_PAYLOADS_SIZE = \
MAX_PACKET_SIZE - PACKET_HR_SIZE - CHUNK_COMM_HDR_SIZE - O_DATA_CHUNK_COMM_HDR_SIZE
MAX_U_DATA_CHUNK_PAYLOADS_SIZE = \
MAX_PACKET_SIZE - PACKET_HR_SIZE - CHUNK_COMM_HDR_SIZE - U_DATA_CHUNK_COMM_HDR_SIZE

# chunk action   chunk type       chunk flag         
# first 2 bits       middle 5 bits    last 3 bits ube    

'''
 00 - Stop processing this parameter; do not process any further
 parameters within this chunk.
 01 - Stop processing this parameter, do not process any further
 parameters within this chunk, and report the unrecognized
 parameter in an ’Unrecognized Parameter’, as described in
 Section 3.2.2.
 10 - Skip this parameter and continue processing.
 11 - Skip this parameter and continue processing but report the
 unrecognized parameter in an ’Unrecognized Parameter’, as
 described in Section 3.2.2.
 
 Chunk Types are encoded such that the highest-order 2 bits specify
 the action that must be taken if the processing endpoint does not
 recognize the Chunk Type.
 00 - Stop processing this SCTP packet and discard it, do not
 process any further chunks within it.
 01 - Stop processing this SCTP packet and discard it, do not
 process any further chunks within it, and report the
 unrecognized chunk in an ’Unrecognized Chunk Type’.
 10 - Skip this chunk and continue processing.
 11 - Skip this chunk and continue processing, but report in an
 ERROR chunk using the ’Unrecognized Chunk Type’ cause of
 error.
 Note: The ECNE and CWR chunk types are reserved for future use of
 Explicit Congestion Notification (ECN); see Appendix A.
'''
ACTION_STOP = int('00000000', 2)  # 00 000000
ACTION_STOP_RPT = int('01000000', 2)  # 01000000
ACTION_SKIP = int('10000000', 2)  # 128  # 10000000
ACTION_SKIP_RPT = int('11000000', 2)  # 192  # 11000000
action2take = ACTION_SKIP_RPT  # setup by user prior to init connection with remote endpoint

# chunk flag  the last 3 low bits in an uint8
CHUNK_FLAG_UBE = int('00000111', 2)  # U1 B1 E1 unordered not fragmnted msg the only msg
CHUNK_FLAG_UB = int('00000110', 2)  # U1 B1 E0 unordered first fragment
CHUNK_FLAG_UE = int('00000101', 2)  # U1 B0 E1 unordered last fragment
CHUNK_FLAG_UM = int('00000100', 2)  # U1 B0 E0 unordered middle fragment
CHUNK_FLAG_OBE = int('00000011', 2)  # U0 B1 E1 ordered not fragmnted msg the only msg
CHUNK_FLAG_OB = int('00000010', 2)  # U0 B1 E0 ordered first fragment
CHUNK_FLAG_OE = int('00000001', 2)  # U0 B0 E1 ordered last fragment
CHUNK_FLAG_OM = int('00000000', 2)  # U0 B0 E0 ordered middle fragment
CHUNK_FLAG_MASK = int('00000111', 2)
CHUNK_FLAG_UMASK = int('00000100', 2)
# chunk type the first 5 high bits in an unit8   UP TO 32 KINDS OF TYPES\
CHUNK_TYPE_FLAG_SIZE = 1
CHUNK_TYPE_DATA = int('00000000', 2)
CHUNK_TYPE_INIT = int('10000000', 2)  # 128
CHUNK_TYPE_SACK = int('01000000', 2) 
CHUNK_TYPE_MASK = int('11111000', 2)

class sctp_msg(object):
    def __init__(self):
        # user need initialize this msg
        self.is_unorder_msg = False
        self.chunk_type = CHUNK_TYPE_DATA
        self.stream_identifier = 0
        self.payload_ptl_itfier = 0
        # type of raw bytes, this is the result of struct.pack(..)
        self.data = None 

class FakeTransport(object):
    def write(self, packet, addr):
        logging.debug("faked write\n")
        p = deepcopy(packet)
        logging.debug("typeof(packet) %s" % type(packet))
        
class Reliabler(object):
    def __init__(self, transport, addr):
        self.transport = transport
        self.addr = addr

        self.max_recv_buffer_size = 1024 * 1024 * 1024  # 1MB
        self.recv_buf = ctypes.create_string_buffer(self.max_recv_buffer_size) 
        self.recvs = {}
        self.total_fragments_size_index = 0
        self.fragments_index = 1
        self.curr_fragments_size_index = 2
        self.max_buffered_fragments_size = 1024
        
        # seq nums
        self.trans_seq_num = 0
        self.sm_seq_nums = [0 for i in xrange(256)]
        
        '''
        # header field 2I
        self.verification_tag = 0  # UINT32
        self.self.checksum = 0  # #UINT32
        
        # chunk header field BH
        self.chunk_type = 0  # UINT8
        self.chunk_flag = 0  # UINT8 [5 bits +CHUNK_FLAG_UBE]
        self.chunk_length = 0  # UINT16
        
        # chunk data header I2HI
        SELF.TSN UINT32
        self.stream_identifier = 0  # UINT16
        self.self.sm_seq_nums[stream_itfier] = 0  # UINT16
        self.payload_protocol_identifier = 0  # UINT32
        
        # User Data variable length padd 4 bytes bounary
        self.chunk_value = bytearray(0) 
        '''
        self.sending_packets = []
        self.sending_packet_pool = []
        for i in xrange(1024): 
            self.sending_packet_pool.append(ctypes.create_string_buffer(MAX_PACKET_SIZE))
        self.unfull_packet_buf = None
        self.unfull_packet_buf_remaining_space = 0
        
        self.received_fragments = [i for i in xrange(1024)]
        self.received_tsns = []
        
        self.verifi = 0
        self.checksum = 0

    def set_on_complete_msg(self, on_complete_msg_cb):
        '''
        when a cpmplete msg is constructed, cb will be invked by reliabler
        to notify the user
        formate
        '''
        self.on_complete_msg_cb = on_complete_msg_cb
    
    def send_user_msg(self, msg):
        msg.chunk_type = CHUNK_TYPE_DATA
        self.send_msg(msg)
        
    def send_msg(self, msg):
        '''
        @param msg: the payloads of the msg in formate of bytearray
         msg is type of list that contains the data chunk as payload in the msg
         msg will be transformed into bytesarray for msg encoding
        @summary: 
         if you want to send a = 1, b=[1,2],
         you can:
         1. msg = bytes(pickle.loads(a)+pickle.loads[b]), then call send_user_msg(msg, msg_id_login) send pickle as string data in utf-8 formate
         2. msg = bytes(bytearray(a)+bytearray(b)), then call send_user_msg(msg, msg_id_login) send binary data
        '''
        
        # aasume this msg is a full packet, will be updated in if else
        # construct packet header     
        self.verifi = 0
        self.checksum = 0
        
        if msg.chunk_type == CHUNK_TYPE_DATA:
            self.handle_data_chunk(msg)
        elif msg.chunk_type == CHUNK_TYPE_INIT:
            self.handle_data_chunk(msg)
        else:
            pass
        
    def handle_data_chunk(self, msg):
        debug_msg = bytearray()
        
        # construct fragment's chunk  header 
        stream_itfier = msg.stream_identifier
        payload_ptc_itf = msg.payload_ptl_itfier
        chunk_type = msg.chunk_type

        if not msg.is_unorder_msg:
            packet_formate = FULL_PACKET_O_DATA_CHUNK_FORMATE
            chunk_formate = O_FULL_DATA_CHUNK_FORMATE
            max_data_chunk_payloads_size = MAX_O_DATA_CHUNK_PAYLOADS_SIZE 
            data_chunk_full_hdr_size = O_DATA_CHUNK_FULL_HR_SIZE
            logging.debug("O packet_formate {%s}, chunk_formate{%s}, max_data_chunk_payloads_size{%d},data_chunk_full_hdr_size{%d]"
            % (packet_formate, chunk_formate, max_data_chunk_payloads_size, data_chunk_full_hdr_size))
        else:
            packet_formate = FULL_PACKET_U_DATA_CHUNK_FORMATE
            chunk_formate = U_FULL_DATA_CHUNK_FORMATE
            max_data_chunk_payloads_size = MAX_U_DATA_CHUNK_PAYLOADS_SIZE 
            data_chunk_full_hdr_size = U_DATA_CHUNK_FULL_HR_SIZE
            logging.debug("U packet_formate {%s}, chunk_formate{%s}, max_data_chunk_payloads_size{%d},data_chunk_full_hdr_size{%d]"
            % (packet_formate, chunk_formate, max_data_chunk_payloads_size, data_chunk_full_hdr_size))
            
        curr_chunk_data_size = len(msg.data)
        curr_rd_offset = 0
        
        if self.unfull_packet_buf is not None:
            if data_chunk_full_hdr_size == O_DATA_CHUNK_FULL_HR_SIZE:  # this is ordered msg we have to test if can hold it again
                if self.unfull_packet_buf_remaining_space <= O_DATA_CHUNK_FULL_HR_SIZE:
                    logging.debug(" self.unfull_packet_buf_remaining_space{%d}<= O_DATA_CHUNK_FULL_HR_SIZE{%d}"
                                  % (self.unfull_packet_buf_remaining_space, O_DATA_CHUNK_FULL_HR_SIZE))
                    self.sending_packets.append(self.unfull_packet_buf[:MAX_PACKET_SIZE - self.unfull_packet_buf_remaining_space])
                    self.unfull_packet_buf = None
                    self.unfull_packet_buf_remaining_space = 0
                     # increament trans_seq_num when this msg fragments are all sent    
                    self.trans_seq_num += 1
                    if self.trans_seq_num > 0xffffffff:
                        self.trans_seq_num = 0 
                    # increament sm_seq_num when this msg fragments are all sent    
                    self.sm_seq_nums[stream_itfier] += 1
                    if self.sm_seq_nums[stream_itfier] > 0xffff:
                        self.sm_seq_nums[stream_itfier] = 0 
                    # finally send all sending packets
                    for packet in self.sending_packets:
                        self.transport.write(packet, self.addr)
                        # @TODO - we cannot  delete the packet until we recive the SACK from receiver
                        # at this moment, just simply clear the list
                        if len(packet) == MAX_PACKET_SIZE:
                            self.sending_packet_pool.append(packet)
                        self.sending_packets.remove(packet)
                    return 
                
            packet_buf = self.unfull_packet_buf
            packey_buf_offset = MAX_PACKET_SIZE - self.unfull_packet_buf_remaining_space
            self.unfull_packet_buf_remaining_space -= data_chunk_full_hdr_size
            
            if curr_chunk_data_size >= self.unfull_packet_buf_remaining_space:  # can write the unfull_packet_buf until it gets full
                logging.debug("curr_chunk_data_size {%d} > self.unfull_packet_buf_remaining_space{%d}" 
                              % (curr_chunk_data_size, self.unfull_packet_buf_remaining_space))
 
                chunk_len = data_chunk_full_hdr_size + self.unfull_packet_buf_remaining_space
                # construct first fragment's chunk value 
                chunk_val = msg.data[ :self.unfull_packet_buf_remaining_space]
                # construct first fragment's chunk flag and len
                if msg.is_unorder_msg:
                    chunk_flag = CHUNK_FLAG_UB  # unordered has no ssn
                    values = (chunk_type | chunk_flag, chunk_len,
                              self.trans_seq_num, stream_itfier, payload_ptc_itf,
                              chunk_val) 
                else:
                    chunk_flag = CHUNK_FLAG_OB
                    values = (chunk_type | chunk_flag, chunk_len,
                                self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                                chunk_val)  
                struct.pack_into((chunk_formate) % self.unfull_packet_buf_remaining_space, packet_buf, packey_buf_offset, *values)
                self.sending_packets.append(packet_buf)# full packet 
                
                if not msg.is_unorder_msg:
                    logging.debug("First O fragmented msg:\n chunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                    \nssn '%d' \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                    self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                else:
                    logging.debug("First U fragmented msg:\n chunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                    \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                    self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                debug_msg += packet_buf[packey_buf_offset + data_chunk_full_hdr_size : 
                                        packey_buf_offset + data_chunk_full_hdr_size + self.unfull_packet_buf_remaining_space]
                    
                curr_chunk_data_size -= self.unfull_packet_buf_remaining_space
                curr_rd_offset = self.unfull_packet_buf_remaining_space
                self.unfull_packet_buf = None
                self.unfull_packet_buf_remaining_space = 0
                
                # increament trans_seq_num for next packet further processing in the below path   
                self.trans_seq_num += 1
                # rollback tsn if needed
                if self.trans_seq_num > 0xffffffff:
                    self.trans_seq_num = 0 
            else:
                logging.debug("curr_chunk_data_size {%d} <= self.unfull_packet_buf_remaining_space{%d}"
                      % (curr_chunk_data_size, self.unfull_packet_buf_remaining_space))
                
                chunk_len = data_chunk_full_hdr_size + curr_chunk_data_size
                # construct first fragment's chunk value 
                chunk_val = msg.data[:]
                # construct first fragment's chunk flag and len
                if msg.is_unorder_msg:
                    chunk_flag = CHUNK_FLAG_UBE  # unordered has no ssn
                    
                    values = (chunk_type | chunk_flag, chunk_len,
                                self.trans_seq_num, stream_itfier, payload_ptc_itf,
                                chunk_val) 
                else:
                    chunk_flag = CHUNK_FLAG_OBE
                    
                    values = (chunk_type | chunk_flag, chunk_len,
                            self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                            chunk_val)  
                struct.pack_into((chunk_formate) % curr_chunk_data_size, packet_buf, packey_buf_offset, *values)
                
                if not msg.is_unorder_msg:
                    logging.debug("O unfragmented msg:\n chunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                    \nssn '%d' \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                    self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    debug_msg += packet_buf[packey_buf_offset + O_DATA_CHUNK_FULL_HR_SIZE : 
                                        packey_buf_offset + O_DATA_CHUNK_FULL_HR_SIZE + curr_chunk_data_size]
                else:
                    logging.debug("U unfragmented msg:\n chunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                    \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                    self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    debug_msg += packet_buf[packey_buf_offset + U_DATA_CHUNK_FULL_HR_SIZE : 
                                        packey_buf_offset + U_DATA_CHUNK_FULL_HR_SIZE + curr_chunk_data_size]
                
                self.unfull_packet_buf_remaining_space -= curr_chunk_data_size
                curr_chunk_data_size = 0
                
                if self.unfull_packet_buf_remaining_space <= data_chunk_full_hdr_size:  # no enough space to hold more chunk
                    logging.debug("set unfull_packet_buf to None remaining_space{%d}<= data_chunk_full_hdr_size{%d}" 
                                  % (self.unfull_packet_buf_remaining_space, data_chunk_full_hdr_size))
                    self.sending_packets.append(packet_buf)
                    self.unfull_packet_buf = None
                    self.unfull_packet_buf_remaining_space = 0
                else:
                    logging.debug("this packet is still not full, so we return to avoid increment ")
                    if binascii.hexlify(debug_msg) != binascii.hexlify(msg.data):
                        assert 0, "debug_msg != msg\n"
                    else:
                        logging.debug("debug_msg good!\n")   
                        
        if curr_chunk_data_size > max_data_chunk_payloads_size:  # This chunk needs to be fragmented into multi packets to carry
            logging.debug("curr_chunk_data_size '%d' > max_data_chunk_payloads_size '%d'" 
            % (curr_chunk_data_size, max_data_chunk_payloads_size))
            
            # calculate the number of fragments and last fragment's chunk data size
            remaining = curr_chunk_data_size % max_data_chunk_payloads_size
            if remaining == 0:
                total_fragments_size = curr_chunk_data_size / max_data_chunk_payloads_size
            else:
                total_fragments_size = ((curr_chunk_data_size - remaining) / max_data_chunk_payloads_size) + 1 
            logging.debug("remaining '%d', total_fragments_size '%d'" % (remaining, total_fragments_size))
            
            chunk_len = data_chunk_full_hdr_size + max_data_chunk_payloads_size
            
            # construct and send other msgs
            for i in xrange(total_fragments_size):
                if len(self.sending_packet_pool) == 0:
                    for i in xrange(1024): 
                        self.sending_packet_pool.append(ctypes.create_string_buffer(MAX_PACKET_SIZE))
                packet_buf = self.sending_packet_pool.pop()
                if i == 0:
                    # construct first fragment's chunk value 
                    chunk_val = msg.data[curr_rd_offset:curr_rd_offset + max_data_chunk_payloads_size]
                    # construct first fragment's chunk flag
                    if msg.is_unorder_msg:
                        logging.debug(" msg.is_unorder_msg")
                        chunk_flag = CHUNK_FLAG_UB if curr_rd_offset == 0 else CHUNK_FLAG_UM
                        values = (self.verifi, self.checksum,
                                    chunk_type | chunk_flag, chunk_len,
                                   self.trans_seq_num, stream_itfier, payload_ptc_itf,
                                   chunk_val) 
                    else:
                        logging.debug(" msg.is_order_msg")
                        chunk_flag = CHUNK_FLAG_OB if curr_rd_offset == 0 else CHUNK_FLAG_OM
                        values = (self.verifi, self.checksum,
                        chunk_type | chunk_flag, chunk_len,
                        self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                        chunk_val)  
                    logging.debug(type(packet_buf))
                    struct.pack_into((packet_formate) % max_data_chunk_payloads_size, packet_buf, 0, *values)
                    
                    if chunk_flag == CHUNK_FLAG_UB:
                        strr = "First U fragmented msg:\n" 
                    elif chunk_flag == CHUNK_FLAG_UM:
                        strr = "Middle U fragmented msg:\n"
                    elif chunk_flag == CHUNK_FLAG_OB:
                         strr = "First O fragmented msg:\n"
                    elif chunk_flag == CHUNK_FLAG_OM:
                         strr = "Middle O fragmented msg:\n"
                    else:
                        logging.error("no such option")    
                        
                    if msg.is_unorder_msg:
                        logging.debug(strr + "chunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                        \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                        self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    else:
                        logging.debug(strr + "chunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                        \nssn '%d' \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                        self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    debug_msg += packet_buf[MAX_PACKET_SIZE - max_data_chunk_payloads_size : ]
                     
                    self.trans_seq_num += 1
                    if self.trans_seq_num > 0xffffffff:
                        self.trans_seq_num = 0
                    
                elif i == total_fragments_size - 1:
                    # construct last fragment's chunk value 
                    chunk_val = msg.data[curr_rd_offset + i * max_data_chunk_payloads_size: ]
                    
                    if remaining == 0:
                        remaining = max_data_chunk_payloads_size
                    chunk_len = data_chunk_full_hdr_size + remaining   
                    
                    # construct last fragment's chunk flag
                    if msg.is_unorder_msg:
                        chunk_flag = CHUNK_FLAG_UE
                        values = (self.verifi, self.checksum,
                        chunk_type | chunk_flag, chunk_len,
                        self.trans_seq_num, stream_itfier, payload_ptc_itf,
                        chunk_val) 
                    else:
                        chunk_flag = CHUNK_FLAG_OE
                        values = (self.verifi, self.checksum,
                        chunk_type | chunk_flag, chunk_len,
                        self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                        chunk_val)
                    logging.debug(type(packet_buf))
                    struct.pack_into((packet_formate) % remaining , packet_buf, 0, *values)     
                       
                    if not msg.is_unorder_msg:
                        logging.debug("Last O Fragmented msg:\nchunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                        \nssn '%d' \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                        self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    else:
                        logging.debug("Last U Fragmented msg: \
                        \nchunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d', \
                        \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                        self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    debug_msg += packet_buf[MAX_PACKET_SIZE - max_data_chunk_payloads_size : MAX_PACKET_SIZE - max_data_chunk_payloads_size + remaining]
                    
                    if remaining > 0:
                        # at least there is one byte user data to carry, only header has no meaning we use uordered data size to get more chances to carry more data
                        if (max_data_chunk_payloads_size - remaining) > U_DATA_CHUNK_FULL_HR_SIZE: 
                            logging.debug("unfull packet\n")
                            self.unfull_packet_buf = packet_buf        
                            self.unfull_packet_buf_remaining_space = max_data_chunk_payloads_size - remaining 
                else:
                    # construct middle fragment's chunk value 
                    chunk_val = msg.data[curr_rd_offset + i * max_data_chunk_payloads_size : curr_rd_offset + (i + 1) * max_data_chunk_payloads_size]
                    
                    # construct middle fragment's chunk flag
                    if msg.is_unorder_msg:
                        chunk_flag = CHUNK_FLAG_UM
                        logging.debug(bin(chunk_type | chunk_flag))
                        logging.debug(bin(chunk_flag))
                        values = (self.verifi, self.checksum,
                        chunk_type | chunk_flag, chunk_len,
                        self.trans_seq_num, stream_itfier, payload_ptc_itf,
                        chunk_val) 
                    else:
                        chunk_flag = CHUNK_FLAG_OM
                        values = (self.verifi, self.checksum,
                        chunk_type | chunk_flag, chunk_len,
                        self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                        chunk_val)
                    struct.pack_into((packet_formate) % max_data_chunk_payloads_size, packet_buf, 0, *values)
                    
                    if not msg.is_unorder_msg:
                        logging.debug("Middle O Fragmented msg:\nchunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                        \nssn '%d' \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                        self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    else:
                        logging.debug("Middle U Fragmented msg:\
                        \nchunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d', \
                        \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                        self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    debug_msg += packet_buf[MAX_PACKET_SIZE - max_data_chunk_payloads_size: ]
                    
                    # only update tsn because fragments belonging to the same msg have same ssn but different tsn
                    self.trans_seq_num += 1
                    if self.trans_seq_num > 0xffffffff:
                        self.trans_seq_num = 0   
                        
                # packet gets full add it to send queue
                self.sending_packets.append(packet_buf)

        elif curr_chunk_data_size == max_data_chunk_payloads_size:  # this is the only chunk this packet can carry
            logging.debug("curr_chunk_data_size == max_data_chunk_payloads_size{%d}\n" % max_data_chunk_payloads_size)
            if len(self.sending_packet_pool) == 0:
                for i in xrange(1024): 
                    self.sending_packet_pool.append(ctypes.create_string_buffer(MAX_PACKET_SIZE))
            packet_buf = self.sending_packet_pool.pop()
            
            # construct first fragment's chunk value 
            chunk_val = msg.data[curr_rd_offset:]
            chunk_len = data_chunk_full_hdr_size + max_data_chunk_payloads_size
            
            # construct this packet's chunk flag
            if msg.is_unorder_msg:
                chunk_flag = CHUNK_FLAG_UBE if curr_rd_offset == 0 else CHUNK_FLAG_UE
                values = (self.verifi, self.checksum,
                chunk_type | chunk_flag, chunk_len,
                self.trans_seq_num, stream_itfier, payload_ptc_itf,
                chunk_val) 
            else:
                chunk_flag = CHUNK_FLAG_OBE if curr_rd_offset == 0 else CHUNK_FLAG_OE
                values = (self.verifi, self.checksum,
                chunk_type | chunk_flag, chunk_len,
                self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                chunk_val)
            struct.pack_into((packet_formate) % max_data_chunk_payloads_size, packet_buf, 0, *values)
            self.sending_packets.append(packet_buf)
            
            strr = "Unfragmented U:\n" if chunk_flag == CHUNK_FLAG_UBE else "Middle fragmented msg:\n"
            if msg.is_unorder_msg:
                logging.debug(strr + "\nchunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d', \
                \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
            else:
                logging.debug(strr + "chunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\n"
               % (chunk_type, chunk_flag, chunk_len,
                  self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier])) 
            debug_msg += packet_buf[MAX_PACKET_SIZE - max_data_chunk_payloads_size: ]
    
        elif curr_chunk_data_size > 0:  # the packet can carry more than one chunk 
            logging.debug("curr_chunk_data_size {%d} > 0:" % curr_chunk_data_size)
            if len(self.sending_packet_pool) == 0:
                for i in xrange(1024): 
                    self.sending_packet_pool.append(ctypes.create_string_buffer(MAX_PACKET_SIZE))
            packet_buf = self.sending_packet_pool.pop()
            
            # construct first fragment's chunk value 
            chunk_val = msg.data[curr_rd_offset:]
            chunk_len = data_chunk_full_hdr_size + curr_chunk_data_size
            
            # construct this packet's chunk flag
            if msg.is_unorder_msg:
                chunk_flag = CHUNK_FLAG_UBE if curr_rd_offset == 0 else CHUNK_FLAG_UE
                values = (self.verifi, self.checksum,
                chunk_type | chunk_flag, chunk_len,
                self.trans_seq_num, stream_itfier, payload_ptc_itf,
                chunk_val) 
            else:
                chunk_flag = CHUNK_FLAG_OBE if curr_rd_offset == 0 else CHUNK_FLAG_OE
                values = (self.verifi, self.checksum,
                chunk_type | chunk_flag, chunk_len,
                self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                chunk_val)
            struct.pack_into((packet_formate) % curr_chunk_data_size, packet_buf, 0, *values)
            
            if chunk_flag == CHUNK_FLAG_UBE:
                strr = "Unfragmented U msg:\n" 
            elif chunk_flag == CHUNK_FLAG_UE:
                strr = "Last U fragmented msg:\n"
            elif chunk_flag == CHUNK_FLAG_OBE:
                 strr = "Unfragmented O msg:\n"
            else:
                strr = "Last O fragmented msg:\n"
            if msg.is_unorder_msg:
                logging.debug(strr + "\nchunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d', \
                \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
            else:
                logging.debug(strr + "chunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\ncomninations '%d,%s'\n"
               % (chunk_type, chunk_flag, chunk_len,
                  self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
            debug_msg += packet_buf[MAX_PACKET_SIZE - max_data_chunk_payloads_size: 
                                    MAX_PACKET_SIZE - max_data_chunk_payloads_size + curr_chunk_data_size] 
            
            # at least there is one byte user data to carry, only header has no meaning 
            if (max_data_chunk_payloads_size - curr_chunk_data_size) > U_DATA_CHUNK_FULL_HR_SIZE: 
                logging.debug("unfull packet setup\n")
                self.unfull_packet_buf = packet_buf        
                self.unfull_packet_buf_remaining_space = max_data_chunk_payloads_size - curr_chunk_data_size
                if binascii.hexlify(debug_msg) != binascii.hexlify(msg.data):
                    logging.debug("%d,%d\n" % (len(debug_msg), len(msg.data)))  
                else:
                    logging.debug("debug_msg good!\n")
            else:
                self.sending_packets.append(packet_buf[:MAX_PACKET_SIZE - max_data_chunk_payloads_size + curr_chunk_data_size])
            
        # increament trans_seq_num when this msg fragments are all sent    
        self.trans_seq_num += 1
        if self.trans_seq_num > 0xffffffff:
            self.trans_seq_num = 0 
        # increament sm_seq_num when this msg fragments are all sent    
        self.sm_seq_nums[stream_itfier] += 1
        if self.sm_seq_nums[stream_itfier] > 0xffff:
            self.sm_seq_nums[stream_itfier] = 0 
            
        # finally send all sending packets
        for packet in self.sending_packets:
            self.transport.write(packet, self.addr)
            # @TODO - we cannot  delete the packet until we recive the SACK from receiver
            # at this moment, just simply clear the list
            if len(packet) == MAX_PACKET_SIZE:
                self.sending_packet_pool.append(packet)
            self.sending_packets.remove(packet)
            
        logging.debug("end of send_user_msg\n")
        if len(debug_msg) > 0 and binascii.hexlify(debug_msg) != binascii.hexlify(msg.data):
            assert 0, "debug_msg != msg\n"
        else:
            logging.debug("debug_msg good!\n")
            
    def recvr(self, datagram):
        '''
        @param [in] datagram:  the datagram received from UDP layer
        @return: bytearrary of the complete payloads to the user
        @summary: it is user's responsibility to decode the payloads
        '''
        # 1.get packet header fields values
        # 2.get chunk header fields values
        #    2.0 read chunk type,
        #        2.1 if chunk type is UBE, skip reassemble framents -> skip msg-ordering -> report to ulp imediately
        #        2.3 if chunk type is UB,   do   reassemble fragments->skip msg-ordering -> report to ulp imediately
         #       2.4 if chunk type is UE,   do   reassemble fragments->skip msg-ordering- > report to ulp imediately
        #        2.5 if chunk type is OBE, skip reassemble framents ->do  msg-ordering -> report to ulp based on ssn 
        #        2.5 if chunk type is OB,   do reassemble framents ->  do  msg-ordering -> report to ulp based on ssn 
        #        2.5 if chunk type is Oe,   do reassemble framents ->  do  msg-ordering -> report to ulp based on ssn 
        
        ret = unpack_from(PACKET_HR_FORMATE, datagram, 0)
        verifi = ret[0]
        checksum = ret[1]
        tsn = ret[2]
        logging.debug("Read packet hdr values:\nverifier{%d}\nchecksum{%d}\ntsn{%d}" % (verifi, checksum, tsn))
        
        unread_bytes = chunks_total_bytes = len(datagram) - PACKET_HR_SIZE
        red_pos = PACKET_HR_SIZE
        logging.debug("unread_bytes{%d}\nred_pos{%d}" % (unread_bytes, red_pos))
        
        # read all chunks contained in this packet
        while unread_bytes > 0: 
            # read chunks comm hdr field values 
            ret = unpack_from(CHUNK_COMM_HDR_FORMATE, datagram, red_pos)
            chunk_type = ret[0] & CHUNK_TYPE_MASK  # use first 5 bits
            chunk_flag = ret[0] & CHUNK_FLAG_MASK  # use last 3 bits
            chunk_length = ret[1]  # UINT16
            red_pos += CHUNK_COMM_HDR_SIZE
            unread_bytes -= CHUNK_COMM_HDR_SIZE
            logging.debug("Read chunks comm hdr field values:\nchunk_type{%d}, chunk_flag{%d}, chunk len{%d}" % (chunk_type, chunk_flag, chunk_length))
            
            # read specific chunk header field values
            logging.debug("Read specifiv chunk header fields values:\n")
            if chunk_type == CHUNK_TYPE_DATA:
                unorder = True if chunk_flag & CHUNK_FLAG_UMASK == 0 else False
                if unorder:
                    formate = U_DATA_CHUNK_COMM_HDR_FORMATE
                    ret = unpack_from(formate, datagram, red_pos)
                    transmit_seq_num = ret[0]  # UINT32
                    stream_identifier = ret[1]  # UINT16
                    payload_protocol_identifier = ret[3]  # UINT32
                    red_pos += O_DATA_CHUNK_FULL_HR_SIZE
                    unread_bytes -= CHUNK_COMM_HDR_SIZE
                    logging.debug("U transmit_seq_num{%d}, stream_identifier{%d}, sm_seq_nums {%d},payload_protocol_identifier{%d}"
                                  % (transmit_seq_num, stream_identifier, sm_seq_nums, payload_protocol_identifier))
                else:
                    formate = O_DATA_CHUNK_COMM_HDR_FORMATE
                    ret = unpack_from(formate, datagram, red_pos)
                    transmit_seq_num = ret[0]  # UINT32
                    stream_identifier = ret[1]  # UINT16
                    sm_seq_nums = ret[2]  # UINT16
                    payload_protocol_identifier = ret[3]  # UINT32
                    red_pos += O_DATA_CHUNK_FULL_HR_SIZE
                    unread_bytes -= CHUNK_COMM_HDR_SIZE
                    logging.debug("U transmit_seq_num{%d}, stream_identifier{%d}, sm_seq_nums {%d},payload_protocol_identifier{%d}"
                                  % (transmit_seq_num, stream_identifier, sm_seq_nums, payload_protocol_identifier))
                logging.debug("unread_bytes{%d}\nred_pos{%d}" % (unread_bytes, red_pos))
                
                if chunk_flag == CHUNK_FLAG_UBE:
                    pass
                
                ret = unpack_from(formate, datagram, red_pos)
                transmit_seq_num = ret[3]  # UINT32
                stream_identifier = ret[4]  # UINT16
                sm_seq_nums = ret[5]  # UINT16
                payload_protocol_identifier = ret[6]  # UINT32
                chunk_data = ret[7] 
                logging.debug("Read chunks fields values: \
                 \nchunl_len {%d} red_pos {%d}\
                 \n chunk_type{%d}\nchunk_flag{%d}\nchunk_length{%d}\ntransmit_seq_num{%d}stream_identifier{%d}\
                 sm_seq_nums{%d}\npayload_protocol_identifier{%d}\n" 
                 % (chunk_length, red_pos,
                      chunk_type, chunk_flag, chunk_length,
                       transmit_seq_num, stream_identifier, sm_seq_nums,
                        payload_protocol_identifier))
                pass
            elif chunk_type == CHUNK_TYPE_INIT:
                pass
            elif chunk_type == CHUNK_TYPE_SACK:
                pass
            
            # store this chunk's tsn  for ack and congestion avoidance @TODOLATER
            self.received_tsns.append(transmit_seq_num)
            self.received_tsns.sort()
            logging.debug("Store this chunk's tsn:\n%s" % self.received_tsns)
            
            logging.debug("Reassemble fragments if needed:")
            # reassemble fragments if needed
            if chunk_flag == CHUNK_FLAG_UBE:
                logging.debug("Unordered UnFragment")
                
                pass
            elif chunk_flag == CHUNK_FLAG_UB:
                logging.debug("First Unordered Fragment")
                pass
            elif chunk_flag == CHUNK_FLAG_UM:
                logging.debug("Middle Unordered Fragment")
                pass
            elif chunk_flag == CHUNK_FLAG_UE:
                logging.debug("Last Unordered Fragment")
                pass
            elif chunk_flag == CHUNK_FLAG_OBE:
                logging.debug("Ordered UnFragment ")
                pass
            elif chunk_flag == CHUNK_FLAG_OB:
                logging.debug("First Ordered Fragment")
                pass
            elif chunk_flag == CHUNK_FLAG_OM:
                logging.debug("Middle Ordered Fragment")
                pass
            elif chunk_flag == CHUNK_FLAG_OE:
                logging.debug("Last Ordered Fragment")
                pass
            
            
        #
        if msg_group_index == 0:  # it is first fragment complete or incomplete
            msg_fragments_size = struct.unpack_from("!H", datagram, 6)[0]
            if msg_fragments_size <= 1:  # this msg is not fragmented and is complete msg
                # simply return it to upper layer
                msg_payload_len = struct.unpack_from("!H", datagram, 8)[0]
                msg_chunk_data = struct.unpack_from("!%ds" % msg_payload_len, datagram, 10)[0]
                self.complete_user_msgs.append(bytes(msg_chunk_data))
                logging.debug("Receive a complete msg stop processing.\n")
                return
            else:  # this is the first frament, it must be a full packet
                msg_payload_len = MAX_PACKET_SIZE - self.msg_group_field_size - self.msg_group_index_field_size
                msg_chunk_data = struct.unpack_from("!%ds" % msg_payload_len, datagram, 8)[0]
                # we extend it to hold all fragments
                if msg_fragments_size > self.max_buffered_fragments_size:
                     self.recvs[msg_group_id][self.fragments_index].extend([x for x in xrange(msg_fragments_size - self.max_buffered_fragments_size)])    
                     self.max_buffered_fragments_size = msg_fragments_size
                self.recvs[msg_group_id][self.total_fragments_size_index] = msg_fragments_size 
                logging.debug("first fragment received, msg_group_index '%d', msg_chunk_size '%d' msg_fragment_size%d\n" 
                      % (msg_group_index, msg_payload_len, msg_fragments_size))
        elif msg_group_index == msg_fragments_size - 1:  # last fragment received
            msg_payload_len = struct.unpack_from("!H", datagram, 6)[0]
            msg_chunk_data = struct.unpack_from("!%ds" % msg_payload_len, datagram, 8)[0]
            logging.debug("last fragment received, msg_group_index '%d', msg_chunk_size '%d' msg_fragment_size%d\n" 
                      % (msg_group_index, msg_payload_len, msg_fragments_size))
        else:  # middle fragments received
            msg_payload_len = MAX_PACKET_SIZE - self.msg_group_field_size - self.msg_group_index_field_size
            msg_chunk_data = struct.unpack_from("!%ds" % msg_chunk_size, datagram, 4)[0]
            logging.debug("middle fragment received, msg_group_index '%d', msg_chunk_size '%d'\n" 
                  % (msg_group_index, msg_payload_len))
        
         # new msg fragment received, initialize it.
        if self.recvs.get(msg_group_id) is None: 
            logging.debug("create a new msg with id '%d'\n" % msg_group_id) 
            self.recvs[msg_group_id] = []
            self.recvs[msg_group_id].append(0)  # total_fragments_size_index
            self.recvs[msg_group_id].append([0 for x in xrange(self.max_buffered_fragments_size)])  # fragments_index
            self.recvs[msg_group_id].append(0)  # curr_fragments_size_index
            
         # we extend it to hold all fragments
        if msg_group_index > self.max_buffered_fragments_size - 1:
            self.recvs[msg_group_id][self.fragments_index].extend([x for x in xrange(msg_group_index - self.max_buffered_fragments_size + 1)])
            self.max_buffered_fragments_size = msg_group_index + 1
        
        # cache the msg_chunk_data 
        self.recvs[msg_group_id][self.fragments_index][msg_group_index] = msg_chunk_data
          
        # update curr received fragments size
        self.recvs[msg_group_id][self.curr_fragments_size_index] += 1
        logging.debug("currently received fragments '%d', total size '%d'\n"
               % (len(self.recvs[msg_group_id][self.curr_fragments_size_index]), self.recvs[msg_group_id][self.total_fragments_size_index]))
        
        # all fragments received and starts to ressembleing
        if self.recvs[msg_group_id][self.curr_fragments_size_index] == self.recvs[msg_group_id][self.total_fragments_size_index]:
            v = self.recvs.pop(msg_group_id)
            fragments = v[self.fragments_index]
            fragments_size = v[self.curr_fragments_size_index]
            fragments_buffered = fragments[0:fragments_size]
            msg = bytearray(0)
            for i in fragments_buffered: msg += i
            self.complete_user_msgs.append(bytes(msg))
            logging.debug("Construct a complete msg.\n")
            
if __name__ == '__main__':
    o = Reliabler(FakeTransport(), "fake addr")
    
    d = sctp_msg()
    d.chunk_type = CHUNK_TYPE_INIT  # CHUNK_TYPE_DATA
    
    msgid = 123
    data = [1, 2, 3]
    bytedata = pickle.dumps(data)  # it has been encoded using asciii encodes single char encode
    
    for i in xrange(1000):
        logging.debug("test very big msg with a new packet")
        d.stream_identifier = randint(0, 1)
        d.is_unorder_msg = randint(0, 1)
        strbuf = ['0' for i in xrange(randint(20, 21))]
        bigdata = ''.join(strbuf)
        msgid = 6
        d.payload_ptl_itfier = msgid 
        buf = ctypes.create_string_buffer(1 + len(bytedata) + len(bigdata))
        pack_into("!B%ds%ds" % (len(bigdata), len(bytedata)), buf, 0, msgid, bytedata, bigdata)
        d.data = buf
        o.send_msg(d)
    
    


        
            
