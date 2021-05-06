# -*- coding: utf-8 -*-
"""
Created on Tue Mar  9 13:43:11 2021

@author: mhamz
"""
import socket 
import threading
import random
import string
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5
from PIL import Image       

head = 64
pnum = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, pnum)
FORMAT = 'utf-8'
leavem = "diss"
random_generator = Random.new().read
key = RSA.generate(1024, random_generator) #generate pub and priv key
publickey = key.publickey() 
#print(type(key))
#print(type(publickey))
private_key = key.exportKey('PEM')
#print(private_key)
public_key = publickey.exportKey('PEM')
#print(public_key)
#print(type(private_key))# pub key export for exchange
#pks = public_key.exportKey("PEM")
#print(type(pks))
#print(len(pks))
#prks = private_key.exportKey("PEM")
#print(type(pks))
#print(len(pks))
#print(pks)
#print(len(pks))
#pks = str(pks)
#print(len(pks))
#pks = pks[2:-1]
#print(pks)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

def decryptDES(enmsg, key):
    iv = enmsg[0:8]
    ciphertxt = enmsg[8:]
    cipher = DES.new(key, DES.MODE_OFB, iv)
    enmess = cipher.decrypt(ciphertxt)
    #print("The decreypted message is " + str(enmess.decode("utf-8")))
    return enmess.decode("utf-8")


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    x = 0
    clientkey = ''
    sessk = ''
    connected = True
    while connected:
        mlen = conn.recv(head).decode(FORMAT)
        if mlen:
            mlen = int(mlen)
            msg = conn.recv(mlen)
            if msg == leavem:
                connected = False
            elif x == 0:
                #print(msg.decode("UTF-8"))
                print(f"Sending public key  to {addr}")
                conn.send(public_key)
                x = x + 1
            elif x == 1:
                clientkey = msg
                print(type(clientkey))
                sessk = sessionkeygen()
                #print(sessk)
                sessk = sessk.encode("UTF-8")
                clientk = RSA.importKey(clientkey)
                
                encrypted = str(clientk.encrypt(sessk, 32))
                #print(encrypted)
                encrypted = encrypted.encode("UTF-8")
                #print(encrypted)
                print(f"[{addr}] with key {clientkey} will be sent the sessionkey encrypted with their public key")
                conn.send(encrypted)
                x = x + 1
            elif x == 2:
                #print(mlen)
                file = open('server_image.jpg', "wb")
                image_chunk = msg
                #print(image_chunk)# stream-based protocol
                file.write(image_chunk)
                img = Image.open('server_image.jpg')
                img.show()
                x = x + 1
            else:
                rectwo = msg
                print(str(rectwo))
                paddedmsg = decryptDES(rectwo, sessk)
                time, actmess = paddedmsg.split('[{at}]')
                print(f"{addr} at time {time} has sent: ")
                print(actmess.replace('0', ''))
                
            
        #print(clientkey)
        #print(sessk)            
            
                
                

    conn.close()
        

def start():
    server.listen()
    print(f"WAITING FOR CLIENTS TO CONNECT TO {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")

def sessionkeygen():
    return ''.join(random.choice(string.ascii_letters) for x in range(8))

#y = sessionkeygen()


print("server is starting...")
start()