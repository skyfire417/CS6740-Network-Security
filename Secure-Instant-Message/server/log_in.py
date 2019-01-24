##  log_in.py for final project
##  Course: CS6740 Network Security
##
##  By: Xiang Zhang, Yunfan Tian

import zmq
import sys
import time
import base64
import argparse
import getpass
import random
import protobuf_pb2
import os

import features
import util

def log_in_server(socket, ident, data, reply, key_iv, log_in_list):
    try:
        flag = 0
        print ("%s wants to log in" %(data.UserName))
        key = key_iv[ident][0]
        iv = key_iv[ident][1]
        if data.UserName in log_in_list:
            print ("%s have already logged in" %(data.UserName))
            reply.TypeNumber = 25
            reply.Note = "You have already logged in, please do not try again"
            reply.C1 = data.C1
            reply.C2 = random.randint(1,10001)
            s_msg = util.aes_en(key, iv, reply.SerializeToString())
            s_msg_signature = util.rsa_sign(s_msg)
            socket.send_multipart([ident, s_msg, s_msg_signature])
            return

        with open("sign_up.txt", 'r') as f:
            for line in f:
                log = line.split("  ")
                name = log[0]
                Hash_password = log[1]
                if name == data.UserName: # check username
                    if util.bcrypt_verify(str(data.Password), Hash_password) == True: # check password

                        log_in_list[data.UserName] = [ident, data.Port]

                        reply.TypeNumber = 21
                        reply.UserName = data.UserName
                        reply.Note = "Welcome to chat, you have already Logged in"
                        reply.C1 = data.C1
                        cha2 = random.randint(1,10001)
                        reply.C2 = cha2

                        s_msg = util.aes_en(key, iv, reply.SerializeToString())
                        s_msg_signature = util.rsa_sign(s_msg)
                        socket.send_multipart([ident, s_msg, s_msg_signature])

                        message = socket.recv_multipart()
                        message_de = util.rsa_de(message[1])
                        log_in_3 = protobuf_pb2.MyProtocol()
                        log_in_3.ParseFromString(message_de)

                        if log_in_3.C2 == cha2:
                            print ("%s have logged in"%(log_in_3.UserName))
                            flag = 1
                        else: 
                            print 'logout the user'
                            flag = 1

                    else: # wrong password
                        reply.TypeNumber = 22
                        reply.Note = "Wrong password, please try again"
                        reply.C1 = data.C1
                        reply.C2 = random.randint(1,10001)
                        s_msg = util.aes_en(key, iv, reply.SerializeToString())
                        s_msg_signature = util.rsa_sign(s_msg)
                        socket.send_multipart([ident, s_msg, s_msg_signature])
                        flag = 1

        if flag == 0: # not signed up yet
            reply.TypeNumber = 25
            reply.Note = "You have not signed up, please sign up first"
            reply.C1 = data.C1
            reply.C2 = random.randint(1,10001)
            s_msg = util.aes_en(key, iv, reply.SerializeToString())
            s_msg_signature = util.rsa_sign(s_msg)
            socket.send_multipart([ident, s_msg, s_msg_signature])

    except: # Error
        key = key_iv[ident][0]
        iv = key_iv[ident][1]
        reply.TypeNumber = 0 
        reply.Error = "Log in Error happen"
        s_msg = util.aes_en(key, iv, reply.SerializeToString())
        s_msg_signature = util.rsa_sign(s_msg)
        socket.send_multipart([ident, s_msg, s_msg_signature])
    

def log_in_client(socket, bind_port, key, iv):
    flag = 1
    while flag == 1:
        log_in_rq = protobuf_pb2.MyProtocol()

        name = raw_input('Please enter your username: ')
        print "=================================================="
        password = getpass.getpass('Please enter your password: ')
        print "=================================================="
        log_in_rq.TypeNumber = 2
        log_in_rq.Type = "Log in"
        log_in_rq.UserName = name
        log_in_rq.Password = password
        log_in_rq.Port = bind_port
        cha1 = random.randint(1,10001) # 1-10000
        log_in_rq.C1 = cha1
        log_in_rq.Key_client = key.encode('base-64')
        log_in_rq.Iv_client = iv.encode('base-64')

        socket.send_multipart([util.rsa_en(log_in_rq.SerializeToString())])

        message = socket.recv_multipart()
        s_msg = message[0]
        s_msg_sig = message[1]

        if util.rsa_verify(s_msg_sig, s_msg) == True: # verify the signature from server
            o_msg = util.aes_de(key, iv, s_msg)

            log_in_resp = protobuf_pb2.MyProtocol()
            log_in_resp.ParseFromString(o_msg)

            if log_in_resp.TypeNumber == 0: # Error
                print log_in_resp.Error
                flag = 1

            if log_in_resp.TypeNumber == 21: # Success
                print log_in_resp.Note
                flag = 0
                if log_in_resp.C1 == cha1:
                    log_in_3 = protobuf_pb2.MyProtocol()
                    log_in_3.TypeNumber = 23
                    log_in_3.UserName = log_in_resp.UserName
                    log_in_3.C2 = log_in_resp.C2

                    socket.send_multipart([util.rsa_en(log_in_3.SerializeToString())])
                    return name
                else:
                    print 'Wrong Challenge, please try it again'
                    log_in_3 = protobuf_pb2.MyProtocol()
                    log_in_3.TypeNumber = 24
                    log_in_3.Error = "Wrong challenge"
                    
                    socket.send_multipart([log_in_3.SerializeToString()])

            if log_in_resp.TypeNumber == 22: # Wrong password
                print log_in_resp.Note
                flag = 1

            if log_in_resp.TypeNumber == 25: # Not sign up
                print log_in_resp.Note
                os._exit(0)
       
