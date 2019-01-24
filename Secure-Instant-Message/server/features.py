##  features.py for final project
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

# check repeat in file (if repeat, delete the repeat item)
def check_repeat(file_name, username):
    f = open(file_name, "r")
    lines = f.readlines()
    f.close()
    f = open(file_name, "w")
    for line in lines:
        log = line.split("  ")
        name = log[0]
        if name != username:
            f.write(line)
    f.close()

# delete the item 
def delete_from_file(file_name, username):
    check_repeat(file_name, username)

# check the repeat item in sign up
def check_repeat_in_sign_up(file_name, username):
    with open("sign_up.txt", 'r') as f: 
        for line in f:
            log = line.split("  ")
            name = log[0]
            Hash_password = log[1]
            if name == username:
                return 1
    return 0
        

# check the time stamp (if timeout, return 0)
def check_time_stamp(time1, time2):
    if time2 - time1 > 100:
        print 'Receive message time out'
        return 0
    else:
        return 1

# print prompt
def print_prompt(c):
    sys.stdout.write(c)
    sys.stdout.flush()

# check session time expired or not (new thread)
def check_session_time(session_key_set, socket_set, ident_set, mutex_socket, mutex_ident, mutex_session):
    delete_name = "ABC"
    while(True):
        time_now = time.time()
        for name in session_key_set:
            session_start_time = session_key_set[name][2]
            if session_start_time - time_now > 2000: # expire after 2000s
                delete_name = name
                break
        if delete_name != "ABC":
            mutex_session.acquire()
            del session_key_set[delete_name]
            mutex_session.release()

            mutex_socket.acquire()
            del socket_set[delete_name]
            mutex_socket.release()

            mutex_ident.acquire()
            del ident_set[delete_name]
            mutex_ident.release()

        delete_name = "ABC"
        time.sleep(60)

# DoS attack defend (new thread)
def dos_attack_defend(black_list, message_attempt):
    message_attempt_previous = {}
    while(True):
        if bool(message_attemp_previous) == True:
            for ident in message_attempt:
                if ident in message_attempt_previous:
                    if message_attempt[ident] - message_attempt_previous[name] > 500: # 500 messages in 60s
                        black_list.append(ident)
        message_attempt_previous = message_attempt
        time.sleep(60)

# check identity in black list or not
def check_in_black_list(ident, black_list):
    if ident in black_list:
        return 1
    else:
        return 0

# receive heartbeat
def heartbeat_server(ident, data, heartbeat, time1):
    heartbeat[ident] = time1


# send heartbeat (new thread)
def heartbeat_client(socket, name):
    hb = protobuf_pb2.MyProtocol()
    hb.TypeNumber = 1234
    hb.Sender_name = name
    hb_en = util.rsa_en(logout_response.SerializeToString())
    socket.send_multipart([util.rsa_en(logout_response.SerializeToString())])
    while(True):
        socket.send_multipart([hb_en])
        time.sleep(300) # 5 mins

# check heartbeat time
def check_heartbeat_time(heartbeat, log_in_list, key_iv):
    while(True):
        time.sleep(300)
        now = time.time()
        for ident in heartbeat:
            if now - heartbeat[ident][1] > 2000: # 2000s
                logout_user = heartbeat[ident][0]
                print ("%s will expired because of lost of heartbeat" %(logout_name))

                for name1 in log_in_list: # check name in list
                    ident1 = log_in_list[name1][0]
                    if name1 == logout_user:
                        continue
                    cha2 = random.randint(1,10001)
                    logout_request.C2 = cha2
                    flag = 0
                    while flag == 0:
                        key1 = key_iv[ident1][0]
                        iv1 = key_iv[ident1][1]
                        send_message = util.aes_en(key1, iv1, logout_request.SerializeToString())
                        socket.send_multipart([ident1, send_message])

                        logout_res = socket.recv_multipart()
                        logout_res_de = util.rsa_de(logout_res[1])
                        logout_response = protobuf_pb2.MyProtocol()
                        logout_response.ParseFromString(logout_res_de)

                        if logout_response.TypeNumber == 101:
                            if logout_response.C2 == cha2 + 1:
                                flag = 1

                del log_in_list[logout_user]
                print ("%s have logged off" %(data.Sender_name))