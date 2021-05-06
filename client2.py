# -*- coding: utf-8 -*-
"""
Created on Tue Mar  9 13:45:13 2021

@author: mhamz
"""

import socket
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime
import base64
from Crypto.PublicKey import RSA
import ast
from Crypto import Random
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5

def encryptDES(msg, key):
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_OFB, iv)
    enmess = cipher.encrypt(msg)
    #print("The encrypted message is " + str(iv) + str(enmess))
    return iv + enmess

def decryptDES(enmsg, key):
    iv = enmsg[0:8]
    ciphertxt = enmsg[8:]
    cipher = DES.new(key, DES.MODE_OFB, iv)
    enmess = cipher.decrypt(ciphertxt)
    #print("The decreypted message is " + str(enmess.decode("utf-8")))
    return enmess.decode("utf-8")

def padding(msg):
    while (len(msg)%8 != 0):
        msg = msg + '0'
    return msg



random_generator = Random.new().read
key = RSA.generate(1024, random_generator) #generate pub and priv key

publickey = key.publickey() # pub key export for exchange

#print(type(key))
#print(type(publickey))
private_key = key.exportKey('PEM')
#print(private_key)
public_key = publickey.exportKey('PEM')
print(type(public_key))
#print(type(private_key))

head = 64
pnum = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = "192.168.56.1"
ADDR = (SERVER, pnum)
sessionkey = ''

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def send(msg):
    message = msg
    mlen = len(message)
    slen = str(mlen).encode(FORMAT)
    slen += b' ' * (head - len(slen))
    client.send(slen)
    client.send(message)
    msgr = client.recv(2048)
    msgr = msgr.decode("UTF-8")
    decrypted = key.decrypt(ast.literal_eval(msgr))
    sessionkey = decrypted.decode(FORMAT)
    print(decrypted)
    return sessionkey
    
def pubrec(msg):
    message = msg.encode("UTF-8")
    mlen = len(message)
    slen = str(mlen).encode(FORMAT)
    slen += b' ' * (head - len(slen))
    client.send(slen)
    client.send(message)
    msgr = client.recv(2048)
    print("The servers public key is: ")
    print(msgr)

def sendmess(msg):
    message = msg
    mlen = len(message)
    slen = str(mlen).encode(FORMAT)
    slen += b' ' * (head - len(slen))
    client.send(slen)
    client.send(message)
    
def sendpic(msg):
    message = msg
    mlen = len(message)
    slen = str(mlen).encode(FORMAT)
    slen += b' ' * (head - len(slen))
    client.send(slen)
    client.send(message)
    

#print(image_data)    
#print(type(image_data))
#print(pks)
#print(len(pks))
#pks = str(pks)
#print(len(pks))
#pks = pks[2:-1].encode("utf-8")
#message = b'encrypt me!'
#public_key = RSA.importKey(pks)
#message = public_key.encrypt(message, 32)
#decrypted = key.decrypt(ast.literal_eval(str(encrypted)))

#print(pks)
pubrec("Requesting inititation of protocol")
sessionkey = send(public_key)
file = open('saturn.jpg', 'rb')
image_data = file.read()
sendpic(image_data)

#print(public_key)
print("Protocol has been completed, below please enter a message or exit to disconnect")
while True:
    
    msg = input()
    if (msg == 'exit' or msg == 'EXIT'):
        break
    else:
        msg = str(datetime.now()) + '[{at}]' + msg 
        msgen = padding(msg)
        msgen = encryptDES(msgen, sessionkey)
        print(msgen)
        sendmess(msgen)
        
        

#send(DISCONNECT_MESSAGE)