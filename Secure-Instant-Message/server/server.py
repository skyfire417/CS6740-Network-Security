##  server.py for final project
##  Course: CS6740 Network Security
##
##  By: Xiang Zhang, Yunfan Tian

import zmq
import sys
import time
import base64
import argparse
import protobuf_pb2

import log_in
import sign_up
import send
import list1
import features
import random
import log_out
import util

# prepare socket in zmq
print 'Server initializing'
context = zmq.Context()

socket = context.socket(zmq.ROUTER)
server_port = "9090"
socket.bind("tcp://*:%s" %(server_port))

key_iv = {} # ident:[key, iv, time]
log_in_list = {} # name:[ident, port_number]

black_list = []
message_attempt = {} # ident:message_received
heartbeat = {} # ident:[name, time]
# receive message and decrypt
try:
    while(True):
        message = socket.recv_multipart()
        ident = message[0]
        #features.check_in_black_list(ident, black_list) = 1 or 0
        message_de = util.rsa_de(message[1])
        reply = protobuf_pb2.MyProtocol()
        data = protobuf_pb2.MyProtocol()
        data.ParseFromString(message_de)

        if data.TypeNumber == 1 or data.TypeNumber == 2:
            key_iv[ident] = [data.Key_client.decode('base-64'), data.Iv_client.decode('base-64')]
        print '*****************************************'
        if data.TypeNumber == 1: # sign up Request
            sign_up.sign_up_server(socket, ident, data, reply, key_iv)

        if data.TypeNumber == 2: # Log in Request
            log_in.log_in_server(socket, ident, data, reply, key_iv, log_in_list)

        if data.TypeNumber == 3: # List request
            list1.list_server(socket, ident, data, reply, key_iv, log_in_list)

        if data.TypeNumber == 4: # Send request Part 1
            send.send_server_step1(socket, ident, data, key_iv, log_in_list)

        if data.TypeNumber == 41: # Send request Part 2
            send.send_server_step2(socket, ident, data, key_iv, log_in_list)

        if data.TypeNumber == 99: # log out request
            log_out.log_out_server(socket, ident, data, key_iv, log_in_list)
        
        #if data.TypeNumber == 1234: # Heartbeat message
        #    time1 = time.time()
        #    features.heartbeat_server(ident, data, heartbeat, time1)

except KeyboardInterrupt:
    socket.close()