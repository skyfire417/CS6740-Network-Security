##  sign_up.py for final project
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

import features
import util

def print_prompt(c):
    sys.stdout.write(c)
    sys.stdout.flush()

def sign_up_server(socket, ident, data, reply, key_iv):
    try:
        print ("%s wants to sign up" %(data.UserName))
        key = key_iv[ident][0]
        iv = key_iv[ident][1]

        write_in_pw = util.bcrypt_hash(str(data.Password)) # get hashed password
        repeat = features.check_repeat_in_sign_up("sign_up.txt", data.UserName) # check repeat

        if repeat == 0:
            with open("sign_up.txt", 'a+') as f: 
                f.write(data.UserName + "  " + write_in_pw + "  \n")

            reply.TypeNumber = 11
            reply.UserName = data.UserName
            reply.Note = "Congratulation, you have signed up successfully"
            reply.C1 = data.C1
            cha2 = random.randint(1,10001)
            reply.C2 = cha2
            s_msg = util.aes_en(key, iv, reply.SerializeToString())
            s_msg_signature = util.rsa_sign(s_msg)
            socket.send_multipart([ident, s_msg, s_msg_signature])

            message = socket.recv_multipart()
            message_de = util.rsa_de(message[1])
            sign_up_3 = protobuf_pb2.MyProtocol()
            sign_up_3.ParseFromString(message_de)

            if sign_up_3.C2 == cha2: # check challenge
                print ("%s have signed up"%(sign_up_3.UserName))
            else: 
                features.delete_from_file("sign_up.txt", data.UserName)
                # delete the sign up information
        else:
            reply.TypeNumber = 999 # repeat
            reply.Note = "0"
            reply.Key = "0"
            reply.Error = "You have registered before, please log in"
            s_msg = util.aes_en(key, iv, reply.SerializeToString())
            s_msg_signature = util.rsa_sign(s_msg)
            socket.send_multipart([ident, s_msg, s_msg_signature])
    except:
        key = key_iv[ident][0]
        iv = key_iv[ident][1]
        reply.TypeNumber = 0
        reply.Note = "0"
        reply.Key = "0"
        reply.Error = "Sign up Error happen"
        s_msg = util.aes_en(key, iv, reply.SerializeToString())
        s_msg_signature = util.rsa_sign(s_msg)
        socket.send_multipart([ident, s_msg, s_msg_signature])

def sign_up_pw():
    flag = 1
    while flag == 1:
        password1 = getpass.getpass('Please enter your password: ')
        print "=================================================="
        password2 = getpass.getpass('Please enter your password again: ')
        print "=================================================="
        if password1 == password2:
            flag = 0
    return password1

def sign_up_client(socket, key, iv):
    flag = 1
    while flag == 1:
        sign_up_rq = protobuf_pb2.MyProtocol()

        name = raw_input('Please enter your username: ')
        print "=================================================="
        print ("Your name is %s" %(name))
        print "=================================================="
        password = sign_up_pw()

        sign_up_rq.TypeNumber = 1
        sign_up_rq.Type = "Sign up"
        sign_up_rq.UserName = name
        sign_up_rq.Password = password
        cha1 = random.randint(1,10001)
        sign_up_rq.C1 = cha1
        sign_up_rq.Key_client = key.encode('base-64')
        sign_up_rq.Iv_client = iv.encode('base-64')

        socket.send_multipart([util.rsa_en(sign_up_rq.SerializeToString())])

        message = socket.recv_multipart()
        s_msg = message[0]
        s_msg_sig = message[1]

        if util.rsa_verify(s_msg_sig, s_msg) == True: # verify server signature
            o_msg = util.aes_de(key, iv, s_msg)

            sign_up_resp = protobuf_pb2.MyProtocol()
            sign_up_resp.ParseFromString(o_msg)

            if sign_up_resp.TypeNumber == 0: # Error
                print sign_up_resp.Error
                flag = 1

            if sign_up_resp.TypeNumber == 999: # Have signed up Error
                print sign_up_resp.Error
                flag = 0

            if sign_up_resp.TypeNumber == 11: # Success
                flag = 0
                if sign_up_resp.C1 == cha1:
                    sign_up_3 = protobuf_pb2.MyProtocol()
                    sign_up_3.TypeNumber = 13
                    sign_up_3.UserName = sign_up_resp.UserName
                    sign_up_3.C2 = sign_up_resp.C2
                    print sign_up_resp.Note
                    socket.send_multipart([util.rsa_en(sign_up_3.SerializeToString())])
                else:
                    print 'Wrong Challenge, please try it again'
                    sign_up_3 = protobuf_pb2.MyProtocol()
                    sign_up_3.TypeNumber = 14
                    sign_up_3.Error = "Wrong challenge"
                    
                    socket.send_multipart([log_in_3.SerializeToString()])