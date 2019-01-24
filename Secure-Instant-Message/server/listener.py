##  listener.py for final project
##  Course: CS6740 Network Security
##
##  By: Xiang Zhang, Yunfan Tian

import zmq
import sys
import time
import base64
import argparse
import protobuf_pb2
import getpass
import threading
import random
import time

import features
import util

# sub socket listener
def client_socket_listener_as_client(socket, chat_socket, mutex, session_key_set): 
    poll = zmq.Poller()
    poll.register(socket, zmq.POLLIN)

    while(True):
        sock = dict(poll.poll())
        if socket in sock and sock[socket] == zmq.POLLIN:
            message1 = socket.recv_multipart()
            msg1 = protobuf_pb2.MyProtocol()
            msg1.ParseFromString(message1[0])

            if msg1.TypeNumber == 8:
                time1 = msg1.Time
                time2 = time.time()
                time_stmp = features.check_time_stamp(time1, time2)
                if time_stmp == 1:
                    message_decode64 = msg1.Message.decode('base-64')
                    this_key = session_key_set[msg1.Sender_name][0]
                    this_iv = session_key_set[msg1.Sender_name][1]
                    message_receive = util.aes_de(this_key, this_iv, message_decode64)
                    print ("\n >>> %s: %s" %(msg1.Sender_name, message_receive))
                    features.print_prompt(' <<< ')
                else:
                    print ("\n >>> %s: %s" %(msg1.Sender_name, msg1.Message)) # should be deleted
                    features.print_prompt(' <<< ')


# chat socket listener
def client_socket_listener_as_server(socket, chat_ident, name, mutex, key, iv, session_key_set, mutex_session_key):
    poll = zmq.Poller()
    poll.register(socket, zmq.POLLIN)

    while(True):
        sock = dict(poll.poll())
        if socket in sock and sock[socket] == zmq.POLLIN:
            message1 = socket.recv_multipart()
            ident = message1[0]
            msg1 = protobuf_pb2.MyProtocol()
            msg1.ParseFromString(message1[1])

            if msg1.TypeNumber == 8:
                time1 = msg1.Time
                time2 = time.time()
                time_stmp = features.check_time_stamp(time1, time2)
                if time_stmp == 1:
                    message_decode64 = msg1.Message.decode('base-64')
                    this_key = session_key_set[msg1.Sender_name][0]
                    this_iv = session_key_set[msg1.Sender_name][1]
                    message_receive = util.aes_de(this_key, this_iv, message_decode64)
                    print ("\n >>> %s: %s" %(msg1.Sender_name, message_receive))
                    features.print_prompt(' <<< ')
                else:
                    print ("\n >>> %s: %s" %(msg1.Sender_name, message_receive)) # should be deleted
                    features.print_prompt(' <<< ')

            if msg1.TypeNumber == 10: # send request
                ticket1 = msg1.Ticket.decode('base-64')

                if util.aes_de(key, iv, ticket1):
                    mutex.acquire()
                    chat_ident[msg1.Sender_name] = ident # add to dictionary
                    mutex.release()

                    msg2 = protobuf_pb2.MyProtocol()
                    msg2.TypeNumber = 102
                    msg2.Chat_to = msg1.Sender_name
                    nonce_b = random.randint(1,10001)
                    msg2.Nb = nonce_b
                    msg2_en = util.aes_en(key, iv, msg2.SerializeToString())
                    socket.send_multipart([ident, msg2_en])

                    message3 = socket.recv_multipart()
                    message3_de = util.aes_de(key, iv, message3[1])
                    msg3 = protobuf_pb2.MyProtocol()
                    msg3.ParseFromString(message3_de)

                    if msg3.Nb == nonce_b:
                        msg4 = protobuf_pb2.MyProtocol()
                        key_ab = msg3.Key_ab.decode('base-64')
                        iv_ab = msg3.Iv_ab.decode('base-64')

                        msg4.TypeNumber = 104
                        nonce_2 = random.randint(1,10001)
                        msg4.N2 = nonce_2
                        msg4_en = util.aes_en(key_ab, iv_ab, msg4.SerializeToString())
                        socket.send_multipart([ident, msg4_en])

                        message5 = socket.recv_multipart()
                        message5_de = util.aes_de(key_ab, iv_ab, message5[1])
                        msg5 = protobuf_pb2.MyProtocol()
                        msg5.ParseFromString(message5_de)

                        if msg5.N2 == (nonce_2 - 1):
                            private_eckey1, public_eckey1, iv1 = util.generate_eckey()

                            msg6 = protobuf_pb2.MyProtocol()
                            msg6.TypeNumber = 106
                            msg6.Sender_name = name
                            msg6.Key_ab = public_eckey1.encode('base-64')
                            msg6.Iv_ab = iv1.encode('base-64')
                            msg6_en = util.aes_en(key_ab, iv_ab, msg6.SerializeToString())
                            socket.send_multipart([ident, msg6_en])

                            message7 = socket.recv_multipart()
                            message7_de = util.aes_de(key_ab, iv_ab, message7[1])
                            msg7 = protobuf_pb2.MyProtocol()
                            msg7.ParseFromString(message7_de)

                            public_eckey2 = msg7.Key_ab.decode('base-64')
                            iv2 = msg7.Iv_ab.decode('base-64')

                            key_ab_session, iv_ab_session = util.generate_shared_key(private_eckey1, public_eckey2, iv1, iv2)

                            session_start_time = int(time.time())
                            mutex_session_key.acquire()
                            session_key_set[msg7.Sender_name] = [key_ab_session, iv_ab_session, session_start_time]
                            mutex_session_key.release()