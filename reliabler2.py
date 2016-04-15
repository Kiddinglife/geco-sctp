import ctypes
from time import sleep
from _struct import unpack_from
from _struct import pack_into
import struct
from copy import deepcopy
import binascii
import cPickle as pickle
import logging
from random import randint
# logging.basicConfig(level=logging.DEBUG,
#                 format='[line:%(lineno)d] %(levelname)s %(message)s',
#                 datefmt='%a, %d %b %Y %H:%M:%S',
#                 filename='myapp.log',
#                 filemode='w')
logging.basicConfig(level=logging.INFO,
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
MAX_PACKET_SIZE = 1500 - 20 - 8  # IP header 20 bytes plus UDP header 8 bytes

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

MAX_INBOUND_STREAM_SIZE = 1024
MAX_OUTBOUND_STREAM_SIZE = 1024

def debug_chunk_flag(chunk_flag_id):
    if chunk_flag_id == CHUNK_FLAG_UBE:
        return "UBE"
    elif chunk_flag_id == CHUNK_FLAG_UB:
        return "UB"
    elif chunk_flag_id == CHUNK_FLAG_UE:
        return "UE"
    elif chunk_flag_id == CHUNK_FLAG_UM:
        return "UM"
    elif chunk_flag_id == CHUNK_FLAG_OBE:
        return "OBE"
    elif chunk_flag_id == CHUNK_FLAG_OB:
        return "OB"
    elif chunk_flag_id == CHUNK_FLAG_OE:
        return "OE"
    elif chunk_flag_id == CHUNK_FLAG_OM:
        return "OM"
        
class user_msg(object):
    def __init__(self):
        # user need initialize this msg
        self.chunk_type = CHUNK_TYPE_DATA
        self.chunk_len = 0
        self.tsn = 0
        self.is_unorder_msg = False
        self.stream_identifier = 0
        self.sm_seq_num = 0
        self.payload_ptl_itfier = 0
        # type of raw bytes, this is the result of struct.pack(..)
        self.data = None 

class FakeTransport(object):
    def __init__(self):
        self.r = None
        
    def write(self, packet, addr):
        self.r.recvr(packet)
        
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
        
        self.max_inbound_stream_size = 1024
        self.max_ordered_msgs_queued_in_stream = 1024
        self.received_user_msgs = [i for i in xrange(self.max_inbound_stream_size)]
        for stream in self.received_user_msgs:
            stream = [i for i in xrange(self.max_ordered_msgs_queued_in_stream)]
        
        self.received_chunk_fragments = []
        self.received_tsns = []
        self.ulpmsgs_valid_indexes = []
        self.ulpmsgs = [[] for i in xrange(MAX_INBOUND_STREAM_SIZE)]
        self.verifi = 0
        self.checksum = 0

    def register_on_msg_received_cb(self, on_msg_received_cb):
        '''
        when a cpmplete msg is constructed, cb will be invked by reliabler
        to notify the user
        formate
        '''
        self.on_msg_received_cb = on_msg_received_cb
        
    def timeouts(self):
        logging.debug("========================timeouts====================")
        if self.unfull_packet_buf is not None:
            self.sending_packets.append(self.unfull_packet_buf[:MAX_PACKET_SIZE - self.unfull_packet_buf_remaining_space])
            logging.debug("sending packets len {%d}\n" % len(self.sending_packets))
            self.unfull_packet_buf = None
            self.unfull_packet_buf_remaining_space = 0
            # finally send all sending packets
            for packet in self.sending_packets:
                self.transport.write(packet, self.addr)
                # @TODO - we cannot  delete the packet until we recive the SACK from receiver
                # at this moment, just simply clear the list
                if len(packet) == MAX_PACKET_SIZE:
                    self.sending_packet_pool.append(packet)
            self.sending_packets = []
            
        # then reassemble chunk fragments
        size = len(self.received_chunk_fragments)
        if size > 0: 
            logging.debug("reassemble fragments:\n")
            sequences = []
            need_delete_fragments_indexs=[] # used for delte all reaseembled fragments
            is_sequenced = False
            self.received_chunk_fragments.sort(cmp=lambda x, y:cmp(x[0], y[0]))  
            can_add_middle = False
            middlesize = 0
            first_fragment_index = None
            for i, fragment in enumerate(self.received_chunk_fragments):
                chunk_tsn = fragment[0]
                logging.info("i {%d}, size {%d}" %(i, size))
                if i < size - 1:
                    next_chunk_tsn = self.received_chunk_fragments[i + 1][0] 
                    is_sequenced = True if (next_chunk_tsn - chunk_tsn) == 1 else False
                    if not is_sequenced:
                        sequences = []
                        can_add_middle = False 
                        is_sequenced = False

                chunk_flag = fragment[1]
                if chunk_flag == CHUNK_FLAG_UB or chunk_flag == CHUNK_FLAG_OB:
                    logging.info("Found First  Fragment")
                    if is_sequenced:
                        first_tsn =  fragment[2].tsn
                        first_fragment_index = i
                        sequences.append((fragment,fragment[2].data))
                        can_add_middle = True
                        middlesize+=1
                        logging.info("debug first fragment tsn {%d}, flag {%s}, size %d" % (fragment[0], debug_chunk_flag(fragment[1]),middlesize))
                    else:
                        logging.info("cannot add first fragment with tsn {%d}, flag {%s}, size {%d}" % (fragment[0], debug_chunk_flag(fragment[1]),middlesize))
                elif chunk_flag == CHUNK_FLAG_UE or chunk_flag == CHUNK_FLAG_OE:
                    logging.info("Found last  Fragment")
                    if can_add_middle:
                        pair = [first_fragment_index, i]
                        need_delete_fragments_indexs.append(pair)
                        middlesize+=1
                        sequences.append((fragment,fragment[2].data))
                        assert len(sequences) == (fragment[2].tsn - first_tsn+1)
                        if middlesize !=  len(sequences):
                            logging.info("{%d,%d}"%(middlesize,len(sequences) -2 ))
                            assert middlesize == len(sequences) 
                        data = ''.join([i[1] for i in sequences])
                        ret = unpack_from("!BH", data, 0)
                        msgid = ret[0]
                        datal = ret[1]
                        assert msgid == 6
                        assert datal == len(data)-3
                        lists = pickle.loads(unpack_from("!%ds" % datal, data, 3)[0])
                        logging.debug("%d, %d"%( len(lists), len(gdata)))
                        assert len(lists) == len(gdata)
                        assert lists == gdata
                        fragment[2].data =  data
                        self.ulpmsgs[fragment[2].stream_identifier].append(fragment[2])
                        if fragment[2].stream_identifier not in self.ulpmsgs_valid_indexes:
                            self.ulpmsgs_valid_indexes.append(fragment[2].stream_identifier)
                        sequences = []
                        can_add_middle = False
                        is_sequenced = False
                        logging.info("debug last fragment tsn {%d}, flag {%s}, size %d" % (fragment[0], debug_chunk_flag(fragment[1]),middlesize))
                        middlesize = 0
                        first_fragment_index = None
                    else:
                        logging.info("cannot add last fragment with tsn {%d}, flag {%s}, size {%d}" % (fragment[0], debug_chunk_flag(fragment[1]),middlesize))
                else:
                    logging.info("Found middle  Fragment")
                    if not is_sequenced:
                        can_add_middle = False
                    if can_add_middle:
                        sequences.append((fragment,fragment[2].data)) 
                        middlesize+=1
                        logging.info("debug middle fragment tsn {%d}, flag {%s}, size %d" % (fragment[0], debug_chunk_flag(fragment[1]),middlesize))
                    else:
                        logging.info("cannot add middle fragment with tsn {%d}, flag {%s}, size {%d}" % (fragment[0], debug_chunk_flag(fragment[1]),middlesize))
                        
            for i in need_delete_fragments_indexs:
                #logging.info(i)
                del self.received_chunk_fragments[i[0]:i[1]+1]
                change = i[1]-i[0]+1
                for i in need_delete_fragments_indexs:
                     i[0]-=change
                     i[1]-=change
                
            
        # then  call back msg_received to notify the ulp the received msgs
        logging.debug("len(self.ulpmsgs){%d,%s}" % (len(self.ulpmsgs_valid_indexes), self.ulpmsgs_valid_indexes))
        for stream_ifier in self.ulpmsgs_valid_indexes:
            msgs = self.ulpmsgs[stream_ifier]
            msgs.sort(cmp=lambda x, y:cmp(x.sm_seq_num, y.sm_seq_num))
            msgs_ = msgs
            msgs = []  # @todo current ilpl doest not queue the msgs,we empty the msgs queue when dispath then to ulp
            self.on_msg_received_cb(stream_ifier, msgs_)
        self.ulpmsgs_valid_indexes = []
        
    def recv_msg(self, stream_id,):
        pass  
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
        logging.debug("=======================sendr:===========================")
        debug_msg = bytearray()
        
        # construct fragment's chunk  header 
        stream_itfier = msg.stream_identifier
        payload_ptc_itf = msg.payload_ptl_itfier
        chunk_type = msg.chunk_type
        logging.debug("si {%d}, ppi{%d},chunk_type{%d}" % (stream_itfier, payload_ptc_itf, chunk_type))
        
        if not msg.is_unorder_msg:
            packet_formate = FULL_PACKET_O_DATA_CHUNK_FORMATE
            chunk_formate = O_FULL_DATA_CHUNK_FORMATE
            max_data_chunk_payloads_size = MAX_O_DATA_CHUNK_PAYLOADS_SIZE 
            data_chunk_full_hdr_size = O_DATA_CHUNK_FULL_HR_SIZE
            logging.debug("O packet_formate {%s}, chunk_formate{%s}, max_data_chunk_payloads_size{%d},data_chunk_full_hdr_size{%d]\n"
            % (packet_formate, chunk_formate, max_data_chunk_payloads_size, data_chunk_full_hdr_size))
        else:
            packet_formate = FULL_PACKET_U_DATA_CHUNK_FORMATE
            chunk_formate = U_FULL_DATA_CHUNK_FORMATE
            max_data_chunk_payloads_size = MAX_U_DATA_CHUNK_PAYLOADS_SIZE 
            data_chunk_full_hdr_size = U_DATA_CHUNK_FULL_HR_SIZE
            logging.debug("U packet_formate {%s},\nchunk_formate{%s},\nmax_data_chunk_payloads_size{%d},\ndata_chunk_full_hdr_size{%d]\n"
            % (packet_formate, chunk_formate, max_data_chunk_payloads_size, data_chunk_full_hdr_size))
            
        curr_chunk_data_size = len(msg.data)
        curr_rd_offset = 0
        
        if self.unfull_packet_buf is not None:
            if data_chunk_full_hdr_size == O_DATA_CHUNK_FULL_HR_SIZE:  # this is ordered msg we have to test if can hold it again
                if self.unfull_packet_buf_remaining_space <= O_DATA_CHUNK_FULL_HR_SIZE:
                    logging.debug(" self.unfull_packet_buf_remaining_space{%d}<= O_DATA_CHUNK_FULL_HR_SIZE{%d}"
                                  % (self.unfull_packet_buf_remaining_space, O_DATA_CHUNK_FULL_HR_SIZE))
                    if self.unfull_packet_buf_remaining_space !=0:
                        self.unfull_packet_buf = self.unfull_packet_buf[:MAX_PACKET_SIZE - self.unfull_packet_buf_remaining_space]
                    self.sending_packets.append(self.unfull_packet_buf)
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
                    self.sending_packets = []
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
                self.sending_packets.append(packet_buf)  # full packet 
                
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
                    \nssn '%d' \ncombinations '%d, %s'\n" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                    self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    debug_msg += packet_buf[packey_buf_offset + O_DATA_CHUNK_FULL_HR_SIZE : 
                                        packey_buf_offset + O_DATA_CHUNK_FULL_HR_SIZE + curr_chunk_data_size]
                else:
                    logging.debug("U unfragmented msg:\n chunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                    \ncombinations '%d, %s'\n" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                    self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    debug_msg += packet_buf[packey_buf_offset + U_DATA_CHUNK_FULL_HR_SIZE : 
                                        packey_buf_offset + U_DATA_CHUNK_FULL_HR_SIZE + curr_chunk_data_size]
                
                self.unfull_packet_buf_remaining_space -= curr_chunk_data_size
                curr_chunk_data_size = 0
                
                if self.unfull_packet_buf_remaining_space <= data_chunk_full_hdr_size:  # no enough space to hold more chunk
                    logging.debug("set unfull_packet_buf to None remaining_space{%d}<= data_chunk_full_hdr_size{%d}" 
                                  % (self.unfull_packet_buf_remaining_space, data_chunk_full_hdr_size))
                    if self.unfull_packet_buf_remaining_space != 0:
                        packet_buf = packet_buf[:MAX_PACKET_SIZE - self.unfull_packet_buf_remaining_space]
                        self.sending_packets.append(packet_buf)
                    self.unfull_packet_buf = None
                    self.unfull_packet_buf_remaining_space = 0
                else:
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
            logging.debug("remaining '%d', total_fragments_size '%d'\n" % (remaining, total_fragments_size))
            
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
                        chunk_flag = CHUNK_FLAG_UB if curr_rd_offset == 0 else CHUNK_FLAG_UM
                        values = (self.verifi, self.checksum,
                                    chunk_type | chunk_flag, chunk_len,
                                   self.trans_seq_num, stream_itfier, payload_ptc_itf,
                                   chunk_val) 
                    else:
                        chunk_flag = CHUNK_FLAG_OB if curr_rd_offset == 0 else CHUNK_FLAG_OM
                        values = (self.verifi, self.checksum,
                        chunk_type | chunk_flag, chunk_len,
                        self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                        chunk_val)  
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
                        \ncombinations '%d, %s'\n" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                        self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    else:
                        logging.debug(strr + "chunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\
                        \nssn '%d' \ncombinations '%d, %s'\n" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
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
                            # increament trans_seq_num when this msg fragments are all sent    
                            self.trans_seq_num += 1
                            if self.trans_seq_num > 0xffffffff:
                                self.trans_seq_num = 0 
                            # increament sm_seq_num when this msg fragments are all sent    
                            self.sm_seq_nums[stream_itfier] += 1
                            if self.sm_seq_nums[stream_itfier] > 0xffff:
                                self.sm_seq_nums[stream_itfier] = 0 
                            return 
                        else:
                            if max_data_chunk_payloads_size != remaining:
                                packet_buf = packet_buf[:MAX_PACKET_SIZE - max_data_chunk_payloads_size + remaining]
                else:
                    # construct middle fragment's chunk value 
                    chunk_val = msg.data[curr_rd_offset + i * max_data_chunk_payloads_size : curr_rd_offset + (i + 1) * max_data_chunk_payloads_size]
                    
                    # construct middle fragment's chunk flag
                    if msg.is_unorder_msg:
                        chunk_flag = CHUNK_FLAG_UM
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
                        \nssn '%d' \ncombinations '%d, %s'\n" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                        self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
                    else:
                        logging.debug("Middle U Fragmented msg:\
                        \nchunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d', \
                        \ncombinations '%d, %s'\n" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
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
                strr = "U unfragmented msg:" 
            elif chunk_flag == CHUNK_FLAG_UE:
                strr = "Last U fragmented msg:"
            elif chunk_flag == CHUNK_FLAG_OBE:
                 strr = "O Unfragmented  msg:"
            else:
                strr = "Last O fragmented msg:"
            if msg.is_unorder_msg:
                logging.debug(strr + "\nchunk_action '%d,%s'\nchunk_type '%d, %s',\nchunk_flag '%d, %s',\nchunk_len '%d',\ntsn '%d',\nsi '%d', \
                \ncombinations '%d, %s'" % (action2take, bin(action2take), chunk_type, bin(chunk_type), chunk_flag, bin(chunk_flag), chunk_len,
                self.trans_seq_num, stream_itfier, chunk_type | chunk_flag, bin(chunk_type | chunk_flag))) 
            else:
                logging.debug(strr + "\nchunk_type '%d',\nchunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\ncomninations '%d,%s'\n"
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
                if max_data_chunk_payloads_size != curr_chunk_data_size:
                    packet_buf = packet_buf[:MAX_PACKET_SIZE - max_data_chunk_payloads_size + curr_chunk_data_size]
                self.sending_packets.append(packet_buf)
            
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
        self.sending_packets = []
            
        if len(debug_msg) > 0 and binascii.hexlify(debug_msg) != binascii.hexlify(msg.data):
            assert "debug_msg != msg\n"
            
    def debug_recvr(self, datagram, debug_str):
        self.recvr(datagram)
        
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
       # logging.debug("=======================recvr:===========================")
        ret = unpack_from(PACKET_HR_FORMATE, datagram, 0)
        verifi = ret[0]
        checksum = ret[1]
        # logging.debug("verifier{%d}checksum{%d}" % (verifi, checksum))
    
        unread_bytes = chunks_total_bytes = len(datagram) - PACKET_HR_SIZE
        red_pos = PACKET_HR_SIZE
        # read all chunks contained in this packet
        while unread_bytes > 0: 
            #logging.debug("unread_bytes{%d}" % unread_bytes)
            # read chunks comm hdr field values 
            ret = unpack_from(CHUNK_COMM_HDR_FORMATE, datagram, red_pos)
            chunk_type = ret[0] & CHUNK_TYPE_MASK  # use first 5 bits
            chunk_flag = ret[0] & CHUNK_FLAG_MASK  # use last 3 bits
            chunk_length = ret[1]  # UINT16
            red_pos += CHUNK_COMM_HDR_SIZE
            unread_bytes -= CHUNK_COMM_HDR_SIZE
            # logging.debug("chunk_type{%d}, chunk_flag{%d}, chunk len{%d}" % (chunk_type, chunk_flag, chunk_length))

            # dispatch based on chunk type
            if chunk_type == CHUNK_TYPE_DATA:
                msg = user_msg()
                msg.chunk_type = chunk_type
                
                unorder = False if (chunk_flag & CHUNK_FLAG_UMASK) == 0 else True
                if unorder:
                    formate = U_DATA_CHUNK_COMM_HDR_FORMATE
                    ret = unpack_from(formate, datagram, red_pos)
                    transmit_seq_num = ret[0]  # UINT32
                    stream_identifier = ret[1]  # UINT16
                    payload_protocol_identifier = ret[2]  # UINT32
                    red_pos += U_DATA_CHUNK_COMM_HDR_SIZE
                    unread_bytes -= U_DATA_CHUNK_COMM_HDR_SIZE
                    chunk_data_len = chunk_length - U_DATA_CHUNK_FULL_HR_SIZE
                    msg.is_unorder_msg = True
                    msg.sm_seq_num = -1
                    # logging.debug("transmit_seq_num{%d}, stream_identifier{%d},payload_protocol_identifier{%d}, chun_data_len{%d}"
                    # % (transmit_seq_num, stream_identifier, payload_protocol_identifier, chunk_data_len))
                else:
                    formate = O_DATA_CHUNK_COMM_HDR_FORMATE
                    ret = unpack_from(formate, datagram, red_pos)
                    transmit_seq_num = ret[0]  # UINT32
                    stream_identifier = ret[1]  # UINT16
                    sm_seq_nums = ret[2]  # UINT16
                    payload_protocol_identifier = ret[3]  # UINT32
                    red_pos += O_DATA_CHUNK_COMM_HDR_SIZE
                    unread_bytes -= O_DATA_CHUNK_COMM_HDR_SIZE
                    chunk_data_len = chunk_length - O_DATA_CHUNK_FULL_HR_SIZE
                    msg.is_unorder_msg = False
                    msg.sm_seq_num = sm_seq_nums
                    # logging.debug("transmit_seq_num{%d}, stream_identifier{%d}, sm_seq_nums {%d},payload_protocol_identifier{%d}, chun_data_len{%d}"
                    # % (transmit_seq_num, stream_identifier, sm_seq_nums, payload_protocol_identifier, chunk_data_len)) 
                    
                chunk_data = unpack_from("%ds" % chunk_data_len, datagram, red_pos)[0]           
                red_pos += chunk_data_len
                unread_bytes -= chunk_data_len
                
                msg.chunk_len = chunk_data_len
                msg.payload_ptl_itfier = payload_protocol_identifier
                msg.tsn = transmit_seq_num
                msg.stream_identifier = stream_identifier
                msg.data = chunk_data
                
                # reassemble fragments and then think about ordering issue
                if chunk_flag == CHUNK_FLAG_UBE:
                    # logging.debug("Unordered UnFragment")
                    # directly report to ulp (payload_length)
                    self.ulpmsgs[msg.stream_identifier].append(msg)
                    if msg.stream_identifier not in  self.ulpmsgs_valid_indexes:
                        self.ulpmsgs_valid_indexes.append(msg.stream_identifier)
                elif chunk_flag == CHUNK_FLAG_UB:
                    # logging.debug("First Unordered Fragment")
                    self.received_chunk_fragments.append((msg.tsn, CHUNK_FLAG_UB, msg))
                elif chunk_flag == CHUNK_FLAG_UM:
                    # logging.debug("Middle Unordered Fragment")
                    self.received_chunk_fragments.append((msg.tsn, CHUNK_FLAG_UM, msg))
                elif chunk_flag == CHUNK_FLAG_UE:
                    # logging.debug("Last Unordered Fragment\n")
                    self.received_chunk_fragments.append((msg.tsn, CHUNK_FLAG_UE, msg))
                elif chunk_flag == CHUNK_FLAG_OBE:
                    # logging.debug("Ordered UnFragment")
                    self.ulpmsgs[msg.stream_identifier].append(msg)
                    if msg.stream_identifier not in  self.ulpmsgs_valid_indexes:
                        self.ulpmsgs_valid_indexes.append(msg.stream_identifier)
                elif chunk_flag == CHUNK_FLAG_OB:
                    # logging.debug("First Ordered Fragment")
                    self.received_chunk_fragments.append((msg.tsn, CHUNK_FLAG_OB, msg))
                elif chunk_flag == CHUNK_FLAG_OM:
                    # logging.debug("Middle Ordered Fragment")
                    self.received_chunk_fragments.append((msg.tsn, CHUNK_FLAG_OM, msg))
                elif chunk_flag == CHUNK_FLAG_OE:
                    # logging.debug("Last Ordered Fragment\n")
                    self.received_chunk_fragments.append((msg.tsn, CHUNK_FLAG_OE, msg))
                
            elif chunk_type == CHUNK_TYPE_INIT:
                pass
            elif chunk_type == CHUNK_TYPE_SACK:
                pass

gdata = [i for i in xrange(8000)]         
dattalen = 0 
   
def on_msg_received_cb(stream_id, msgs):
    logging.debug("stream ifier{%d}, msgs len {%d}" % (msgs[0].stream_identifier, len(msgs)))
#     for test_stream_id in xrange(10):
#         if stream_id == test_stream_id:
#             for msg in msgs:
#                 ret = unpack_from("!BH", msg.data, 0)
#                 msgid = ret[0]
#                 datal = ret[1]
#                # logging.debug("msgid{%d}, datal len{%d, %d}" % (msgid, datal,dattalen ))
#                 #assert msgid == 6
#                 #assert dattalen == datal
#                 if msgid == 6:
#                     lists = pickle.loads(unpack_from("!%ds" % datal, msg.data, 3)[0])
#                    # logging.debug("msgid{%d}, litsts len{%d}" % (msgid, len(lists)))
# #                     for i, v in enumerate(data):
# #                         assert lists[i] == v             
                        
if __name__ == '__main__':
    msgid = 123
    bytedata = pickle.dumps(gdata)  # it has been encoded using asciii encodes single char encode
    dattalen = len(bytedata)
    t = FakeTransport()
    o = Reliabler(t, "fake addr")
    t.r = o
    o.register_on_msg_received_cb(on_msg_received_cb)  
    
    d = user_msg()
    d.chunk_type = CHUNK_TYPE_DATA
    for i in xrange(1000):
        d.stream_identifier = randint(0, 10)
        d.is_unorder_msg = randint(0, 1)
        msgid = 6
        d.payload_ptl_itfier = msgid 
        buf = ctypes.create_string_buffer(1 + 2 + len(bytedata))
        values = (msgid, len(bytedata), bytedata)
        pack_into("!BH%ds" % (len(bytedata)), buf, 0, *values)
        d.data = buf
        o.send_user_msg(d)  
    o.timeouts()


        
            
