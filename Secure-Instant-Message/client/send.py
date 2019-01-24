##  send.py for final project
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

import util

# the first part for server response
def send_server_step1(socket, ident, data, key_iv, log_in_list):
    try:
        sender_name = data.Sender_name
        target = data.Chat_to
        print ("%s wants to chat with %s" %(sender_name, target))

        key = key_iv[ident][0]
        iv = key_iv[ident][1]

        flag = 0
        for name in log_in_list: # check name is logged in or not
            if name == data.Chat_to:
                target_port_number = log_in_list[name][1]
                target_ident = log_in_list[name][0]
                flag = 1

        if flag == 0: # Offline response
            send_request2 = protobuf_pb2.MyProtocol()
            send_request2.TypeNumber = 0
            send_request2.Type = "Send"
            send_request2.Sender_name = data.Sender_name
            send_request2.Chat_to = data.Chat_to
            send_request2.Error = "The user is off line"
            send_request2_en = util.aes_en(key, iv, send_request2.SerializeToString())
            socket.send_multipart([ident, send_request2_en])
            return 0
        else: # Success response
            key1 = key_iv[target_ident][0]
            iv1 = key_iv[target_ident][1]
            ticket_to_client = protobuf_pb2.MyProtocol()
            ticket_to_client.TypeNumber = 51
            ticket_to_client.Type = "ticket1"
            ticket_to_client.Sender_name = data.Sender_name
            ticket_en = util.aes_en(key1, iv1, ticket_to_client.SerializeToString())
 
            send_request2 = protobuf_pb2.MyProtocol()
            send_request2.TypeNumber = 42
            send_request2.Type = "Send"
            send_request2.Sender_name = data.Sender_name
            send_request2.Chat_to = data.Chat_to
            send_request2.Port = int(target_port_number)
            send_request2.Ticket = ticket_en.encode('base-64')
            send_request2_en = util.aes_en(key, iv, send_request2.SerializeToString())
            socket.send_multipart([ident, send_request2_en])

            return 1

    except: # Error response
            send_request2 = protobuf_pb2.MyProtocol()
            send_request2.TypeNumber = 0
            send_request2.Type = "Send"
            send_request2.Sender_name = data.Sender_name
            send_request2.Chat_to = data.Chat_to
            send_request2.Error = "Send Part 1 Error happen"
            send_request2_en = util.aes_en(key, iv, send_request2.SerializeToString())
            socket.send_multipart([ident, send_request2_en])
            return 0

# the second part for server response
def send_server_step2(socket, ident, data, key_iv, log_in_list):
    try:
        key = key_iv[ident][0]
        iv = key_iv[ident][1]
        for name in log_in_list: # get the ident of target
            if name == data.Chat_to:
                target_port_number = log_in_list[name][1]
                target_ident = log_in_list[name][0]

        key1 = key_iv[target_ident][0] # get target's key and iv
        iv1 = key_iv[target_ident][1]

        message2 = data.Note.decode('base-64')
        message2_de = util.aes_de(key1, iv1, message2)

        if message2 != False:
            msg2 = protobuf_pb2.MyProtocol()
            msg2.ParseFromString(message2_de)

            ticket_to_B = protobuf_pb2.MyProtocol()
            ticket_to_B.TypeNumber = 103
            key_ab, iv_ab = util.key_xor(key, key1, iv, iv1)
            ticket_to_B.Key_ab = key_ab.encode('base-64')
            ticket_to_B.Iv_ab = iv_ab.encode('base-64')
            ticket_to_B.Sender_name = data.Sender_name
            ticket_to_B.Nb = msg2.Nb
            ticket = ticket_to_B.SerializeToString()
            ticket_en = util.aes_en(key1, iv1, ticket)

            send_request4 = protobuf_pb2.MyProtocol()
            send_request4.TypeNumber = 44
            send_request4.N1 = data.N1
            send_request4.Chat_to = data.Chat_to
            send_request4.Key_ab = key_ab.encode('base-64')
            send_request4.Iv_ab = iv_ab.encode('base-64')
            send_request4.Ticket = ticket_en.encode('base-64')
            send_request4_en = util.aes_en(key, iv, send_request4.SerializeToString())
            socket.send_multipart([ident, send_request4_en])

    except:
        send_request4 = protobuf_pb2.MyProtocol()
        send_request4.TypeNumber = 0
        send_request4.Error = "Send Part 2 Error happen"
        send_request4_en = util.aes_en(key, iv, send_request4.SerializeToString())
        socket.send_multipart([ident, send_request4_en])

# send request for who request send to server
def send_client(socket, name, connect_name, chat_socket, mutex, key, iv, session_key_set, mutex_session_key):
    send_request1 = protobuf_pb2.MyProtocol()
    send_request1.TypeNumber = 4
    send_request1.Type = "Send"
    send_request1.Sender_name = name
    send_request1.Chat_to = connect_name
    socket.send_multipart([util.rsa_en(send_request1.SerializeToString())])

    send_rq2 = socket.recv_multipart()
    send_rq2_de = util.aes_de(key, iv, send_rq2[0])
    send_request2 = protobuf_pb2.MyProtocol()
    send_request2.ParseFromString(send_rq2_de)

    if send_request2.TypeNumber == 0: # Error
        print send_request2.Error
    
    if send_request2.TypeNumber == 42: # Success
        port = send_request2.Port
        context = zmq.Context()
        sub_socket = context.socket(zmq.DEALER)
        server = "localhost"
        sub_socket.connect("tcp://%s:%s" %(server, port))

        mutex.acquire()
        chat_socket[connect_name] = sub_socket
        mutex.release()

        msg1 = protobuf_pb2.MyProtocol()
        msg1.TypeNumber = 10
        msg1.Sender_name = name
        msg1.Chat_to = connect_name
        msg1.Ticket = send_request2.Ticket
        sub_socket.send_multipart([msg1.SerializeToString()])

        message2 = sub_socket.recv_multipart()

        send_request3 = protobuf_pb2.MyProtocol()
        send_request3.TypeNumber = 41
        send_request3.Sender_name = name
        send_request3.Chat_to = connect_name
        nonce_1 = random.randint(1,10001)
        send_request3.N1 = nonce_1
        send_request3.Note = message2[0].encode('base-64')
        socket.send_multipart([util.rsa_en(send_request3.SerializeToString())])

        send_rq4 = socket.recv_multipart()
        send_rq4_de = util.aes_de(key, iv, send_rq4[0])
        send_request4 = protobuf_pb2.MyProtocol()
        send_request4.ParseFromString(send_rq4_de)

        if send_request4.TypeNumber == 0: # Error
            print send_request4.Error

        if send_request4.TypeNumber == 44: # Success
            ticket_to_B = send_request4.Ticket

            key_ab = send_request4.Key_ab.decode('base-64')
            iv_ab = send_request4.Iv_ab.decode('base-64')
            sub_socket.send_multipart([ticket_to_B.decode('base-64')])

            message4 = sub_socket.recv_multipart()
            msg4_de = util.aes_de(key_ab, iv_ab, message4[0])
            msg4 = protobuf_pb2.MyProtocol()
            msg4.ParseFromString(msg4_de)
            msg5 = protobuf_pb2.MyProtocol()
            msg5.TypeNumber = 105
            msg5.N2 = msg4.N2 - 1
            msg5_en = util.aes_en(key_ab, iv_ab, msg5.SerializeToString())
            sub_socket.send_multipart([msg5_en])

            message6 = sub_socket.recv_multipart()
            msg6_de = util.aes_de(key_ab, iv_ab, message6[0])
            msg6 = protobuf_pb2.MyProtocol()
            msg6.ParseFromString(msg6_de)

            public_eckey1 = msg6.Key_ab.decode('base-64')
            iv1 = msg6.Iv_ab.decode('base-64')

            if msg6.TypeNumber == 106: # Success
                private_eckey2, public_eckey2, iv2 = util.generate_eckey()

                msg7 = protobuf_pb2.MyProtocol()
                msg7.TypeNumber == 107
                msg7.Sender_name = name
                msg7.Key_ab = public_eckey2.encode('base-64')
                msg7.Iv_ab = iv2.encode('base-64')
                msg7_en = util.aes_en(key_ab, iv_ab, msg7.SerializeToString())
                sub_socket.send_multipart([msg7_en])
                key_ab_session, iv_ab_session = util.generate_shared_key(private_eckey2, public_eckey1, iv2, iv1)

                session_start_time = int(time.time())
                mutex_session_key.acquire()
                session_key_set[connect_name] = [key_ab_session, iv_ab_session, session_start_time]
                mutex_session_key.release()
                return 1





        


        






