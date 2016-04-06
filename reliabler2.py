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
@remeber_myself_why_not_assign_each_chunk_data_a_individual_tsn_for_IP_based_implementation?
1. build on UDP, you can receive a complete datagram from recvfrom(), packet bounary is obvious
so you can assign a unique tsn to a complete packet and each of carried user-data-chunks in it shared the same tsn
2. build on IP layer, packet bounary is anbious, in other words, what you receive from IP layer is blocks of bytes and 
there is no way to distiguse the user-data-chunk fragments bonary. So, we have to assign tsn to each of user-data-chunk
the core algo to reaasemble fragments is sequencial numbers assigned to each fragments just like puzzling games !
'''

# constants
MAX_PACKET_SIZE = 60  # 1500 - 20 - 8 # IP header 20 bytes plus UDP header 8 bytes
PACKET_HR_SIZE = 8

STREAM_SEQ_NUM_SIZE = 2
CHUNK_COMMON_HR_SIZE = 4  # chunk header field 2BH chunk_type  chunk_flag chunk_length ALL CHUNKS HAVE THIS HR
O_MSG_CHUNK_HR_SIZE = 16  # # ORDERED chunk common header field 2BH + msg chunk header header I2HI
U_MSG_CHUNK_HR_SIZE = O_MSG_CHUNK_HR_SIZE-STREAM_SEQ_NUM_SIZE
MAX_O_CHUNK_DATA_SIZE = MAX_PACKET_SIZE - PACKET_HR_SIZE - O_MSG_CHUNK_HR_SIZE
MAX_U_CHUNK_DATA_SIZE = MAX_PACKET_SIZE - PACKET_HR_SIZE - U_MSG_CHUNK_HR_SIZE

O_PACKET_FORMATE = '!2I2BHI2HI%ds'
O_CHUNK_FORMATE = '!2BHIHI%ds'
U_PACKET_FORMATE = '!2I2BHIHI%ds'
U_CHUNK_FORMATE = '!2BHIHI%ds'

UBE = 7  # U1 B1 E1 unordered not fragmnted msg the only msg
UB = 6  # U1 B1 E0 unordered first fragment
UE = 5  # U1 B0 E1 unordered last fragment
UM = 4  # U1 B0 E0 unordered middle fragment
OBE = 3  # U0 B1 E1 ordered not fragmnted msg the only msg
OB = 2  # U0 B1 E0 ordered first fragment
OE = 1  # U0 B0 E1 ordered last fragment
OM = 0  # U0 B0 E0 ordered middle fragment


# chuk_types
CT_MSG = 0
CT_INIT = 1
CT_SACK = 2

class sctp_msg(object):
    def __init__(self):
        # user need initialize this msg
        self.is_unorder_msg = False
        self.stream_identifier = 0
        self.payload_ptl_itfier = 0
        # type of bytes, this is the result of struct.pack(..)
        self.data = None 

class FakeTransport(object):
    def write(self, packet, addr):
        logging.debug("faked write\n")
        p = deepcopy(packet)
        
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
        self.checksum = 0  # #UINT32
        
        # chunk header field 2BH
        self.chunk_type = 0  # UINT8
        self.chunk_flag = 0  # UINT8 [5 bits +UBE]
        self.chunk_length = 0  # UINT16
        
        # chunk data header I2HI
        self.transmit_seq_num = 0  # UINT32
        self.stream_identifier = 0  # UINT16
        self.self.sm_seq_nums[stream_itfier] = 0  # UINT16
        self.payload_protocol_identifier = 0  # UINT32
        
        # User Data variable length padd 4 bytes bounary
        self.chunk_value = bytearray(0) 
        '''
        packet_formate = '!2I2BHI2HI%ds'
        chunk_formate = '!2BHI2HI%ds'
        
        self.packet_hdr_size = 8
        self.msg_fragments_field_size = 2
        self.msg_payload_field_size = 2
        
        self.on_complete_msg_cb = None
        self.complete_user_msgs = []
        self.user_msgs_fragments = []
        
        self.sending_packets = []
        self.sending_packet_pool = []
        for i in xrange(1024): 
            self.sending_packet_pool.append(ctypes.create_string_buffer(MAX_PACKET_SIZE))
        self.unfull_packet_buf = None
        self.unfull_packet_buf_remaining_space = 0
        
        self.received_fragments = [i for i in xrange(1024)]
        self.received_tsns = []
    def set_on_complete_msg(self, on_complete_msg_cb):
        '''
        when a cpmplete msg is constructed, cb will be invked by reliabler
        to notify the user
        formate
        '''
        self.on_complete_msg_cb = on_complete_msg_cb

        
    def send_user_msg(self, msg):
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
        debug_msg = bytearray()
        
        # aasume this msg is a full packet, will be updated in if else
        # construct packet header     
        verifi = 0
        checksum = 0
        
        # construct fragment's chunk header 
        chunk_type = CT_MSG  # THIS IS USER DATA @TODO- may add control chunk later
         
        # construct fragment's chunk  header 
        stream_itfier = msg.stream_identifier
        payload_ptc_itf = msg.payload_ptl_itfier
        
        if not msg.is_unorder_msg:
            packet_formate = O_PACKET_FORMATE
            chunk_formate = O_CHUNK_FORMATE
            MAX_CHUNK_DATA_SIZE = MAX_O_CHUNK_DATA_SIZE 
            MSG_CHUNK_HR_SIZE = O_MSG_CHUNK_HR_SIZE
        else:
            packet_formate = U_PACKET_FORMATE
            chunk_formate = U_CHUNK_FORMATE
            MAX_CHUNK_DATA_SIZE = MAX_U_CHUNK_DATA_SIZE 
            MSG_CHUNK_HR_SIZE = U_MSG_CHUNK_HR_SIZE
          
        curr_chunk_data_size = len(msg.data)
        curr_rd_offset = 0
        
        if self.unfull_packet_buf is not None:
            if MSG_CHUNK_HR_SIZE == O_MSG_CHUNK_HR_SIZE: # this is ordered msg we have to test if can hold it again
                if self.unfull_packet_buf_remaining_space <= O_MSG_CHUNK_HR_SIZE:
                    self.sending_packets.append(packet_buf)
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
                        self.sending_packet_pool.append(packet)
                        self.sending_packets.remove(packet)
                    return 
                
            packet_buf = self.unfull_packet_buf
            packey_buf_offset = MAX_PACKET_SIZE - self.unfull_packet_buf_remaining_space
            self.unfull_packet_buf_remaining_space -= MSG_CHUNK_HR_SIZE
            
            if curr_chunk_data_size > self.unfull_packet_buf_remaining_space:  # can write the unfull_packet_buf until it gets full
                logging.debug("A  curr_chunk_data_size {%d} > self.unfull_packet_buf_remaining_space{%d}" 
                              % (curr_chunk_data_size, self.unfull_packet_buf_remaining_space))
 
                chunk_len = MSG_CHUNK_HR_SIZE + self.unfull_packet_buf_remaining_space
                
                # construct first fragment's chunk value 
                chunk_val = msg.data[ :self.unfull_packet_buf_remaining_space]
                # construct first fragment's chunk flag and len
                if msg.is_unorder_msg:
                    chunk_flag = UB # unordered has no ssn
                    values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, payload_ptc_itf,
                           chunk_val) 
                else:
                    chunk_flag = OB
                    values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                           chunk_val)  
                struct.pack_into((chunk_formate) % self.unfull_packet_buf_remaining_space, packet_buf, packey_buf_offset, *values)
                self.sending_packets.append(packet_buf)
                
                if not msg.is_unorder_msg:
                    logging.debug("First O Fragmented:\nchunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier])) 
                else:
                    logging.debug("First U Fragmented:\nchunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier)) 
                debug_msg += packet_buf[packey_buf_offset + MSG_CHUNK_HR_SIZE : 
                                        packey_buf_offset + MSG_CHUNK_HR_SIZE + self.unfull_packet_buf_remaining_space]
                    
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
                logging.debug("B  curr_chunk_data_size {%d} <= self.unfull_packet_buf_remaining_space{%d}"
                      % (curr_chunk_data_size, self.unfull_packet_buf_remaining_space))
                
                chunk_len = MSG_CHUNK_HR_SIZE + curr_chunk_data_size
                # construct first fragment's chunk value 
                chunk_val = msg.data[:]
                # construct first fragment's chunk flag and len
                if msg.is_unorder_msg:
                    chunk_flag = UBE # unordered has no ssn
                    values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, payload_ptc_itf,
                           chunk_val) 
                else:
                    chunk_flag = OBE
                    values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                           chunk_val)  
                struct.pack_into((chunk_formate) % curr_chunk_data_size, packet_buf, packey_buf_offset, *values)
                
                if not msg.is_unorder_msg:
                    logging.debug("Unfragmented msg:\nchunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier])) 
                    debug_msg += packet_buf[packey_buf_offset + O_MSG_CHUNK_HR_SIZE : 
                                        packey_buf_offset + O_MSG_CHUNK_HR_SIZE +curr_chunk_data_size]
                else:
                    logging.debug("Unfragmented msg:\nchunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier)) 
                    debug_msg += packet_buf[packey_buf_offset + U_MSG_CHUNK_HR_SIZE : 
                                        packey_buf_offset + U_MSG_CHUNK_HR_SIZE + curr_chunk_data_size]
                
                self.unfull_packet_buf_remaining_space -= curr_chunk_data_size
                curr_chunk_data_size = 0
                
                if self.unfull_packet_buf_remaining_space <= MSG_CHUNK_HR_SIZE:  # no enough space to hold more chunk
                    logging.debug("C set unfull_packet_buf to None remaining_space{%d}<= MSG_CHUNK_HR_SIZE{%d}" 
                                  % ( self.unfull_packet_buf_remaining_space,MSG_CHUNK_HR_SIZE))
                    self.sending_packets.append(packet_buf)
                    self.unfull_packet_buf = None
                    self.unfull_packet_buf_remaining_space = 0
                else:
                    logging.debug("D this packet is still not full, so we return to avoid increment ")
                    if binascii.hexlify(debug_msg) != binascii.hexlify(msg.data):
                        assert 0, "debug_msg != msg\n"
                    else:
                        logging.debug("debug_msg good!\n")
                        
                    # increament sm_seq_num because we still have space for next msg
                    self.sm_seq_nums[stream_itfier] += 1
                    if  self.sm_seq_nums[stream_itfier] > 0xffff:
                            self.sm_seq_nums[stream_itfier] = 0 
                    return  # this packet is still not full, so we return to avoid increment 
                        
        if curr_chunk_data_size > MAX_CHUNK_DATA_SIZE:  # This chunk needs to be fragmented into multi packets to carry
            logging.debug("D - curr_chunk_data_size '%d' > MAX_CHUNK_DATA_SIZE '%d'\n" 
                  % (curr_chunk_data_size, MAX_CHUNK_DATA_SIZE))
            
            # calculate the number of fragments and last fragment's chunk data size
            remaining = curr_chunk_data_size % MAX_CHUNK_DATA_SIZE
            if remaining == 0:
                total_fragments_size = curr_chunk_data_size / MAX_CHUNK_DATA_SIZE
            else:
                total_fragments_size = ((curr_chunk_data_size - remaining) / MAX_CHUNK_DATA_SIZE) + 1 
            logging.debug("E -  remaining '%d', total_fragments_size '%d'\n" % (remaining, total_fragments_size))
            
            chunk_len = MSG_CHUNK_HR_SIZE + MAX_CHUNK_DATA_SIZE
            
            # construct and send other msgs
            for i in xrange(total_fragments_size):
                if len(self.sending_packet_pool) == 0:
                    for i in xrange(1024): 
                        self.sending_packet_pool.append(ctypes.create_string_buffer(MAX_PACKET_SIZE))
                packet_buf = self.sending_packet_pool.pop()
                if i == 0:
                    # construct first fragment's chunk value 
                    chunk_val = msg.data[curr_rd_offset:curr_rd_offset + MAX_CHUNK_DATA_SIZE]
                    # construct first fragment's chunk flag
                    if msg.is_unorder_msg:
                        chunk_flag = UB if curr_rd_offset == 0 else UM
                        values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, payload_ptc_itf,
                           chunk_val) 
                    else:
                        chunk_flag = OB if curr_rd_offset == 0 else OM
                        values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                           chunk_val)  
                    struct.pack_into((packet_formate) % MAX_CHUNK_DATA_SIZE, packet_buf, 0, *values)
                    
                    if chunk_flag == UB:
                        strr = "First U fragmented msg:\n" 
                    elif chunk_flag == UM:
                        strr = "Middle U fragmented msg:\n"
                    elif chunk_flag == OB:
                         strr = "Middle O fragmented msg:\n"
                    else:
                         strr = "Middle O fragmented msg:\n"
                         
                    if msg.is_unorder_msg:
                        logging.debug(strr+"chunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier])) 
                    else:
                        logging.debug(strr+"chunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier)) 
                    debug_msg += packet_buf[MAX_PACKET_SIZE - MAX_CHUNK_DATA_SIZE : ]
                    
                elif i == total_fragments_size - 1:
                    # construct last fragment's chunk value 
                    chunk_val = msg.data[curr_rd_offset + i * MAX_CHUNK_DATA_SIZE: ]
                    
                    if remaining == 0:
                        remaining = MAX_CHUNK_DATA_SIZE
                    chunk_len = MSG_CHUNK_HR_SIZE + remaining   
                    
                    # construct last fragment's chunk flag
                    if msg.is_unorder_msg:
                        chunk_flag = UE
                        values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, payload_ptc_itf,
                           chunk_val) 
                    else:
                        chunk_flag = OE
                        values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                           chunk_val)  
                    struct.pack_into((packet_formate) % remaining , packet_buf, 0, *values)     
                       
                    if not msg.is_unorder_msg:
                        logging.debug("Last O Fragmented:\nchunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier])) 
                    else:
                        logging.debug("Last U Fragmented:\nchunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier)) 
                    debug_msg += packet_buf[MAX_PACKET_SIZE - MAX_CHUNK_DATA_SIZE : MAX_PACKET_SIZE - MAX_CHUNK_DATA_SIZE + remaining]
                    
                    if remaining > 0:
                        # at least there is one byte user data to carry, only header has no meaning we use uordered data size to get more chances to carry more data
                        if (MAX_CHUNK_DATA_SIZE - remaining) > U_MSG_CHUNK_HR_SIZE: 
                            logging.debug("unfull packet\n")
                            self.unfull_packet_buf = packet_buf        
                            self.unfull_packet_buf_remaining_space = MAX_CHUNK_DATA_SIZE - remaining 
                            # increament sm_seq_num for next send
                            self.sm_seq_nums[stream_itfier] += 1
                            # rollback ssn if needed
                            if  self.sm_seq_nums[stream_itfier] > 0xffff:
                                 self.sm_seq_nums[stream_itfier] = 0 
                            return
                else:
                    # construct first fragment's chunk value 
                    chunk_val = msg.data[curr_rd_offset + i * MAX_CHUNK_DATA_SIZE : curr_rd_offset + (i + 1) * MAX_CHUNK_DATA_SIZE]
                    
                    # construct middle fragment's chunk flag
                    if msg.is_unorder_msg:
                        chunk_flag = UM
                        values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, payload_ptc_itf,
                           chunk_val) 
                    else:
                        chunk_flag = OM
                        values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                           chunk_val) 
                    struct.pack_into((packet_formate) % MAX_CHUNK_DATA_SIZE, packet_buf, 0, *values)
                    
                    if not msg.is_unorder_msg:
                        logging.debug("Middle O Fragmented:\nchunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier])) 
                    else:
                        logging.debug("Middle U Fragmented:\nchunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\n"
                       % (chunk_type, chunk_flag, chunk_len, 
                          self.trans_seq_num, stream_itfier)) 
                    debug_msg += packet_buf[MAX_PACKET_SIZE - MAX_CHUNK_DATA_SIZE: ]
                    
                self.sending_packets.append(packet_buf)
                self.trans_seq_num += 1
                # rollback tsn if needed
                if self.trans_seq_num > 0xffffffff:
                    self.trans_seq_num = 0
                    
        elif curr_chunk_data_size == MAX_CHUNK_DATA_SIZE:  # this is the only chunk this packet can carry
            logging.debug("curr_chunk_data_size == MAX_CHUNK_DATA_SIZE{%d}\n" % MAX_CHUNK_DATA_SIZE)
            if len(self.sending_packet_pool) == 0:
                for i in xrange(1024): 
                    self.sending_packet_pool.append(ctypes.create_string_buffer(MAX_PACKET_SIZE))
            packet_buf = self.sending_packet_pool.pop()
            
            # construct first fragment's chunk value 
            chunk_val = msg.data[curr_rd_offset:]
            chunk_len = MSG_CHUNK_HR_SIZE + MAX_CHUNK_DATA_SIZE
            
            # construct this packet's chunk flag
            if msg.is_unorder_msg:
                chunk_flag = UBE if curr_rd_offset == 0 else UE
                values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, payload_ptc_itf,
                           chunk_val) 
            else:
                chunk_flag = OBE if curr_rd_offset == 0 else OE
                values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                           chunk_val) 
            struct.pack_into((packet_formate) % MAX_CHUNK_DATA_SIZE, packet_buf, 0, *values)
            self.sending_packets.append(packet_buf)
            
            strr = "Unfragmented U:\n" if chunk_flag == UBE else "Middle fragmented msg:\n"
            if msg.is_unorder_msg:
                logging.debug(strr+"chunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\n"
               % (chunk_type, chunk_flag, chunk_len, 
                  self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier])) 
            else:
                logging.debug(strr+"chunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\n"
               % (chunk_type, chunk_flag, chunk_len, 
                  self.trans_seq_num, stream_itfier)) 
            debug_msg += packet_buf[MAX_PACKET_SIZE - MAX_CHUNK_DATA_SIZE: ]
    
        elif curr_chunk_data_size > 0:  # the packet can carry more than one chunk 
            logging.debug("curr_chunk_data_size {%d} > 0:" % curr_chunk_data_size)
            if len(self.sending_packet_pool) == 0:
                for i in xrange(1024): 
                    self.sending_packet_pool.append(ctypes.create_string_buffer(MAX_PACKET_SIZE))
            packet_buf = self.sending_packet_pool.pop()
            
            # construct first fragment's chunk value 
            chunk_val = msg.data[curr_rd_offset:]
            chunk_len = MSG_CHUNK_HR_SIZE + curr_chunk_data_size
            
            # construct this packet's chunk flag
            if msg.is_unorder_msg:
                chunk_flag = UBE if curr_rd_offset == 0 else UE
                values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, payload_ptc_itf,
                           chunk_val) 
            else:
                chunk_flag = OBE if curr_rd_offset == 0 else OE
                values = (chunk_type, chunk_flag, chunk_len,
                           self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier], payload_ptc_itf,
                           chunk_val) 
            struct.pack_into((packet_formate) % curr_chunk_data_size, packet_buf, 0, *values)
            
            if chunk_flag == UBE:
                strr = "Unfragmented U msg:\n" 
            elif chunk_flag == UE:
                strr = "Last U fragmented msg:\n"
            elif chunk_flag == OBE:
                 strr = "Unfragmented O msg:\n"
            else:
                strr = "Last O fragmented msg:\n"
            if msg.is_unorder_msg:
                logging.debug(strr+"chunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\nssn '%d'\n"
                % (chunk_type, chunk_flag, chunk_len, 
               self.trans_seq_num, stream_itfier, self.sm_seq_nums[stream_itfier])) 
            else:
                logging.debug(strr+"chunk_type '%d',chunk_flag '%d',\nchunk_len '%d',\ntsn '%d',\nsi '%d',\n"
                % (chunk_type, chunk_flag, chunk_len, 
                self.trans_seq_num, stream_itfier))    
            debug_msg += packet_buf[MAX_PACKET_SIZE - MAX_CHUNK_DATA_SIZE: 
                                    MAX_PACKET_SIZE - MAX_CHUNK_DATA_SIZE + curr_chunk_data_size] 
            
            # at least there is one byte user data to carry, only header has no meaning 
            if (MAX_CHUNK_DATA_SIZE - curr_chunk_data_size) > U_MSG_CHUNK_HR_SIZE: 
                logging.debug("unfull packet setup\n")
                self.unfull_packet_buf = packet_buf        
                self.unfull_packet_buf_remaining_space = MAX_CHUNK_DATA_SIZE - curr_chunk_data_size
                if binascii.hexlify(debug_msg) != binascii.hexlify(msg.data):
                    logging.debug("%d,%d\n" % (len(debug_msg), len(msg.data)))  
                else:
                    logging.debug("debug_msg good!\n")
                    
                # increament sm_seq_num for next send
                self.sm_seq_nums[stream_itfier] += 1
                # rollback ssn if needed
                if  self.sm_seq_nums[stream_itfier] > 0xffff:
                    self.sm_seq_nums[stream_itfier] = 0 
                return
            else:
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
            self.sending_packet_pool.append(packet)
            self.sending_packets.remove(packet)
            
        logging.debug("end of send_user_msg\n")
        if binascii.hexlify(debug_msg) != binascii.hexlify(msg.data):
            assert 0, "debug_msg != msg\n"
        else:
            logging.debug("debug_msg good!\n")
            
    def recvr(self, datagram):
        '''
        @param [in] datagram:  the datagram received from UDP layer
        @return: bytearrary of the complete payloads to the user
        @summary: it is user's responsibility to decode the payloads
        '''
        
        ret = unpack_from("!2I", datagram, 0)
        verifi = ret[0]
        checksum = ret[1]
        logging.debug("Read packet hdr values:\nverifier{%d}\nchecksum{%d}\n" % (verifi, checksum))
        
        chunks_total_bytes = len(datagram) - PACKET_HR_SIZE
        chunk_len_read_offset = PACKET_HR_SIZE + 2
        # read all chunks contained in this packet
        while (chunks_total_bytes - (chunk_len_read_offset - 2)) > 0: 
            chunk_length = unpack_from("!H", datagram, chunk_len_read_offset)[0]
            chunk_len_read_offset += chunk_length
            
            # read chunks fields values
            ret = unpack_from((chunk_formate) % (chunk_length - O_MSG_CHUNK_HR_SIZE), packet, chunk_len_read_offset - 2)
            chunk_type = ret[0]  # UINT8
            chunk_flag = ret[1]  # UINT8 [5 bits +UBE]
            chunk_length = ret[2]  # UINT16
            transmit_seq_num = ret[3]  # UINT32
            stream_identifier = ret[4]  # UINT16
            sm_seq_nums = ret[5]  # UINT16
            payload_protocol_identifier = ret[6]  # UINT32
            chunk_data = ret[7] 
            logging.debug("Read chunks fields values: \
             \nchunl_len {%d} chunk_len_read_offset {%d}\
             \n chunk_type{%d}\nchunk_flag{%d}\nchunk_length{%d}\ntransmit_seq_num{%d}stream_identifier{%d}\
             sm_seq_nums{%d}\npayload_protocol_identifier{%d}\n" 
             % (chunk_length, chunk_len_read_offset,
                  chunk_type, chunk_flag, chunk_length,
                   transmit_seq_num, stream_identifier, sm_seq_nums,
                    payload_protocol_identifier))
            
            # store this chunk's tsn  for ack and congestion avoidance @TODOLATER
            self.received_tsns.append(transmit_seq_num)
            self.received_tsns.sort()
            logging.debug("Store this chunk's tsn:\n%s"%self.received_tsns)
            
            logging.debug("Reassemble fragments if needed:")
            # reassemble fragments if needed
            if chunk_flag == UBE:
                logging.debug("Unordered UnFragment")
                
                pass
            elif chunk_flag == UB:
                logging.debug("First Unordered Fragment")
                pass
            elif chunk_flag == UM:
                logging.debug("Middle Unordered Fragment")
                pass
            elif chunk_flag == UE:
                logging.debug("Last Unordered Fragment")
                pass
            elif chunk_flag == OBE:
                logging.debug("Ordered UnFragment ")
                pass
            elif chunk_flag == OB:
                logging.debug("First Ordered Fragment")
                pass
            elif chunk_flag == OM:
                logging.debug("Middle Ordered Fragment")
                pass
            elif chunk_flag == OE:
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
    
    SEND_FILES_STREAM = 0
    SEND_USER_DATA_STREAM = 1
    
    d = sctp_msg()
    
    msgid = 123
    data = [1, 2, 3]
    bytedata = pickle.dumps(data)  # it has been encoded using asciii encodes single char encode
    buf = ctypes.create_string_buffer(len(bytedata) + 1)
    pack_into("!B%ds" % len(bytedata), buf, 0, msgid, bytedata)
    ret = unpack_from("!B%ds" % len(bytedata), buf, 0)
    msgid_ = ret[0]
    data_ = pickle.loads(ret[1])
    
    assert msgid == msgid_
    assert data == data_
    
#     logging.debug("test unpacket")
#     d.is_unorder_msg = False
#     d.stream_identifier = SEND_FILES_STREAM
#     d.payload_ptl_itfier = msgid
#     d.data = buf
#     o.send_user_msg(d)
#     assert  len(bytedata) + 1 == 19
#     assert MAX_PACKET_SIZE - o.unfull_packet_buf_remaining_space == 16 + 8 + len(bytedata) + 1
#     ret = unpack_from((o.formate) % (len(bytedata) + 1), o.unfull_packet_buf, 0)
#     assert ret[0] == 0
#     assert ret[1] == 0
#     assert ret[2] == CT_MSG
#     assert ret[3] == OBE
#     assert ret[4] == 16 + len(bytedata) + 1
#     assert ret[5] == 0
#     assert ret[6] == 0
#     assert ret[7] == 0
#     assert ret[8] == msgid  # procol itfier
#     ret = unpack_from("!B%ds" % len(bytedata), ret[9], 0)
#     assert ret[0] == msgid
#     assert pickle.loads(ret[1]) == data
# 
#     d.stream_identifier = SEND_USER_DATA_STREAM
#     d.is_unorder_msg = True
#     o.send_user_msg(d)
#     assert MAX_PACKET_SIZE - o.unfull_packet_buf_remaining_space == 16 + 8 + len(bytedata) + 1 + 16 + len(bytedata) + 1
#     ret = unpack_from((o.chunk_formate) % (len(bytedata) + 1), o.unfull_packet_buf, 16 + 8 + len(bytedata) + 1)
#     assert ret[0] == CT_MSG
#     assert ret[1] == UBE
#     assert ret[2] == 16 + len(buf)
#     assert ret[3] == 0
#     assert ret[4] == 1
#     assert ret[5] == 0
#     assert ret[6] == msgid  # procol itfier
#     ret = unpack_from("!B%ds" % len(bytedata), ret[7], 0)
#     assert pickle.loads(ret[1]) == data
#     assert ret[0] == msgid
#     
#     logging.debug("test fragmented msg")
#     d.stream_identifier = SEND_USER_DATA_STREAM
#     d.is_unorder_msg = False
#     buf = ctypes.create_string_buffer(len(bytedata) + 4)
#     msgid = 6553555
#     d.payload_ptl_itfier = msgid 
#     pack_into("!I%ds" % len(bytedata), buf, 0, msgid, bytedata)
#     d.data = buf
#     o.send_user_msg(d)
#     assert len(o.sending_packets) == 1
#     assert len(o.sending_packets[0]) == 100
#     ret = unpack_from((o.chunk_formate) % 6, o.sending_packets[0],
#                       16 + 8 + len(bytedata) + 1 + 16 + len(bytedata) + 1)
#     assert ret[0] == CT_MSG
#     assert ret[1] == OB
#     assert ret[2] == 22
#     assert ret[3] == 0
#     assert ret[4] == 1
#     assert ret[5] == 1
#     assert ret[6] == msgid
#     p1 = ret[7]
#     assert len(p1) == 6
#     
#     ret = unpack_from((o.formate) % 16, o.unfull_packet_buf, 0)
#     assert ret[0] == 0
#     assert ret[1] == 0
#     assert ret[2] == CT_MSG
#     assert ret[3] == OE
#     assert ret[4] == 32
#     assert ret[5] == 1
#     assert ret[6] == 1
#     assert ret[7] == 1
#     assert ret[8] == msgid  # procol itfier
#     p2 = ret[9]
#     assert len(p2) == 16
#     # 拼接内存快
#     # 方法一：快
#     # recvbuf = ctypes.create_string_buffer(len(bytedata) + 4) # this is more efficiently way because you only need allocate one mmeory
#     # pack_into("!6s16s",recvbuf,0, p1,p2)
#     # 方法二　slow and many memory frgments because 
#    # recvbuf = p1+p2 
#    # 方法三　等同于方法一 非常快　推荐使用。
#     recvbuf = ''.join((p1, p2)) 
#     ret = unpack_from("!I%ds" % len(bytedata), recvbuf, 0)
#     assert ret[0] == msgid
#     assert pickle.loads(ret[1]) == data
#     
#     logging.debug("test big msg")
#     d.stream_identifier = SEND_USER_DATA_STREAM
#     d.is_unorder_msg = False
#     strbuf = ['%d' % i for i in xrange(66)]
#     bigdata = ''.join(strbuf)
#     msgid = 6553556
#     d.payload_ptl_itfier = msgid 
#     buf = ctypes.create_string_buffer(4 + len(bytedata) + len(bigdata))
#     pack_into("!I%ds%ds" % (len(bigdata), len(bytedata)), buf, 0, msgid, bytedata, bigdata)
#     d.data = buf
#     o.send_user_msg(d)
#     
#     logging.debug("test very small msg")
#     d.stream_identifier = SEND_USER_DATA_STREAM
#     d.is_unorder_msg = True
#     strbuf = ['0' for i in xrange(1)]
#     bigdata = ''.join(strbuf)
#     msgid = 6
#     d.payload_ptl_itfier = msgid 
#     buf = ctypes.create_string_buffer(1 + len(bytedata) + len(bigdata))
#     pack_into("!B%ds%ds" % (len(bigdata), len(bytedata)), buf, 0, msgid, bytedata, bigdata)
#     d.data = buf
#     o.send_user_msg(d)
#     
#     logging.debug("test just-size msg")
#     d.stream_identifier = SEND_USER_DATA_STREAM
#     d.is_unorder_msg = True
#     strbuf = ['0' for i in xrange(MAX_CHUNK_DATA_SIZE-4-len(bytedata))]
#     bigdata = ''.join(strbuf)
#     msgid = 6553556
#     d.payload_ptl_itfier = msgid 
#     buf = ctypes.create_string_buffer(4 + len(bytedata) + len(bigdata))
#     assert 4 + len(bytedata) + len(bigdata) == MAX_CHUNK_DATA_SIZE
#     pack_into("!I%ds%ds" % (len(bigdata), len(bytedata)), buf, 0, msgid, bytedata, bigdata)
#     d.data = buf
#     o.send_user_msg(d)
#     
#     logging.debug("test very big msg with a new packet")
#     d.stream_identifier = SEND_USER_DATA_STREAM
#     d.is_unorder_msg = True
#     strbuf = ['0' for i in xrange(123434)]
#     bigdata = ''.join(strbuf)
#     msgid = 6
#     d.payload_ptl_itfier = msgid 
#     buf = ctypes.create_string_buffer(1 + len(bytedata) + len(bigdata))
#     pack_into("!B%ds%ds" % (len(bigdata), len(bytedata)), buf, 0, msgid, bytedata, bigdata)
#     d.data = buf
#     o.send_user_msg(d)
    for i in xrange(10000):
        logging.debug("test very big msg with a new packet")
        d.stream_identifier = SEND_USER_DATA_STREAM
        d.is_unorder_msg = True
        strbuf = ['0' for i in xrange(randint(600, 800))]
        bigdata = ''.join(strbuf)
        msgid = 6
        d.payload_ptl_itfier = msgid 
        buf = ctypes.create_string_buffer(1 + len(bytedata) + len(bigdata))
        pack_into("!B%ds%ds" % (len(bigdata), len(bytedata)), buf, 0, msgid, bytedata, bigdata)
        d.data = buf
        o.send_user_msg(d)
    
    


        
            
