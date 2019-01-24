##  list1.py for final project
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
import time
import random

import features
import util

def list_server(socket, ident, data, reply, key_iv, log_in_list):
    try:
        print("%s wants to list" %(data.Sender_name))
        key = key_iv[ident][0]
        iv = key_iv[ident][1]
        listname = "Logged in:  "

        for name in log_in_list: # print log in list
            listname = listname + name + "  "
        reply.TypeNumber = 32
        reply.Note = listname
        cha2 = random.randint(1,10001)
        reply.C2 = cha2
        s_msg = util.aes_en(key, iv, reply.SerializeToString())
        socket.send_multipart([ident, s_msg])

    except: # Error
        key = key_iv[ident][0]
        iv = key_iv[ident][1]
        reply.TypeNumber = 0
        reply.Note = "List Error happen"
        reply.Key = "0"
        reply.Error = "List Error happen"
        s_msg = util.aes_en(key, iv, reply.SerializeToString())
        socket.send_multipart([ident, s_msg])
    
    else: # confirm receive
        list_rq3 = socket.recv_multipart()
        list_rq3_de = util.rsa_de(list_rq3[1])
        list_request3 = protobuf_pb2.MyProtocol()
        list_request3.ParseFromString(list_rq3_de)
        if list_request3.C2 == cha2:
            print 'List complete'


def list_client(socket, name, key, iv):
    list_request1 = protobuf_pb2.MyProtocol()
    list_request1.TypeNumber = 3
    list_request1.Type = "List"
    list_request1.Sender_name = name
    list_request1.C1 = random.randint(1,10001)
    socket.send_multipart([util.rsa_en(list_request1.SerializeToString())])

    list_rq2 = socket.recv_multipart()
    s_msg = list_rq2[0]
    o_msg = util.aes_de(key, iv, s_msg)

    list_request2 = protobuf_pb2.MyProtocol()
    list_request2.ParseFromString(o_msg)
    print list_request2.Note

    list_request3 = protobuf_pb2.MyProtocol()
    list_request3.Note = "Confirm"
    list_request3.Sender_name = name
    list_request3.C2 = list_request2.C2
    socket.send_multipart([util.rsa_en(list_request3.SerializeToString())])

