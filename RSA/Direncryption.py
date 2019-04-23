# -*- coding: utf-8 -*-
"""
Created on Mon Apr 22 20:48:17 2019

@author: Mark
"""

import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
#module to encrypt a string value
def MyfileEncryptMAC(filepath,Encryptionkey,HMACKey):
   
    with open(filepath, 'rb') as f:
        data = f.read()
    encryptedFileData = MyEncrypt(data,Encryptionkey,HMACKey)
    ext = os.path.splitext(filepath)[1]
    
    encryptedFileData += (Encryptionkey,HMACKey,ext)
    
    
    
    jsonstring = json.dumps(str(encryptedFileData[0]))

    
    
    with open(filepath + '.json', 'w+') as encfile:
       json.dump(jsonstring, encfile)  
      
       
    encfile.close()  
    os.remove(filepath)
    
    return encryptedFileData

def MyfileDecrypt(filepath, IV, tag, EncryptionKey,HMACKey, ext):
    with open(filepath, 'rb') as f:
        data = f.read()
   
    fileName = filePath + ext
    plaintext = MyDecrypt(data, IV, tag, EncryptionKey, HMACKey)
    result = open(fileName, 'wb')
    result.write(plaintext)
    
    
def MyEncrypt(message, Encryptionkey, HMACkey):
    if len(Encryptionkey) < 32:
        return "Error. Key must be 32 bytes"
    
    backend = default_backend()
    IV = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    message = padded_data
    cipher = Cipher(algorithms.AES(Encryptionkey), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    C = encryptor.update(message) + encryptor.finalize()
    h = hmac.HMAC(Encryptionkey, hashes.SHA256(), backend=default_backend())
    h.update(C)
    tag = h.finalize()
    return (C, IV, tag)


#module to decrypt a string value
def MyDecrypt(ciphertext, IV, tag, Encryptionkey, HMACkey):

    cipher = Cipher(algorithms.AES(Encryptionkey), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    paddedPlaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(paddedPlaintext) + unpadder.finalize()
    return plaintext

#generate keys public and private 
def Generatekeys():
    
    
    #create key object
    backend = default_backend()
    key = rsa.generate_private_key(backend=backend, public_exponent=65537, key_size=2048)
    
    #private key
    private_key = key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
    with open("private_Key.pem", 'wb') as private_pem:
        private_pem.write(private_key)
        private_pem.close()
        Privatekey = 'private_Key.pem'
        
    #public key 
    public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    with open("public_Key.pem", 'wb') as public_pem:
        public_pem.write(public_key)
        public_pem.close()   
        Publickey = 'public_Key.pem'
        
    return Publickey, Privatekey
    

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
     #Call MyfileEncrypt
     Encryptionkey = os.urandom(32)
     HMACKey = os.urandom(32)
     ciphertext = MyfileEncryptMAC(filepath,Encryptionkey,HMACKey)
     msg = Encryptionkey +  HMACKey
     
     if os.path.exists(RSA_Publickey_filepath):
         key = RSA.importKey(open(RSA_Publickey_filepath).read())
         RSACipher = PKCS1_OAEP.new(key)
         RSACiphertext = RSACipher.encrypt(msg)
     else: 
        #public key 
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        with open("public_Key.pem", 'wb') as public_pem:
            public_pem.write(public_key)
            public_pem.close()
            key = RSA.importKey(open(RSA_Publickey_filepath).read())
            RSACipher = PKCS1_OAEP.new(key)
            RSACiphertext = RSACipher.encrypt(msg)
     
     
     return RSACiphertext,ciphertext
     
     
def MyRSADecrypt(filepath,RSACiphertext, Cipher, IV, tag, ext, RSA_Privatekey_filepath):
    
     key = RSA.importKey(open(RSA_Privatekey_filepath).read())
     RSACipher = PKCS1_OAEP.new(key)
     message = RSACipher.decrypt(RSACiphertext)
     Encryptionkey = message[:32]
     HMACKey = message[-32:]
     MyfileDecrypt(filepath+ext, IV, tag, Encryptionkey, HMACKey, ext)


def getallfiles(path):
    dir_path = os.path.abspath(path)
    dirs = []
    for dirName, subDirList, fileList in os.walk(dir_path):
        for fname in fileList:
            if(fname != 'data.json'):
                dirs.append(fname)
    return dirs

def RSAEncryptAllfiles(path,RSA_Publickey_filepath):
    #Generatekeys();
    dir_path = os.path.abspath(path)
    dirs = []
    RSACiphertext = []
    Ciphertext = []
    for dirName, subDirList, fileList in os.walk(dir_path):
        for fname in fileList:
           RSACiphertext, Ciphertext = MyRSAEncrypt(fname , RSA_Publickey_filepath)
    
     
    return RSACiphertext, Ciphertext
    
def RSADecryptAllfiles(path,Ciphertext, RSACiphertext,RSA_Privatekey_filepath):
    dirs = getallfiles(path)
    for file_name in dirs:
        tag = Ciphertext[2] 
        IV = Ciphertext[1]
        ext = Ciphertext[5]
        MyRSADecrypt(file_name,RSACiphertext,Ciphertext,IV, tag, ext,'privateKey2.pem')
#Generatekeys()    

path = 'encdir'
#works
RSACiphertext, Ciphertext = RSAEncryptAllfiles(path,'publicKey2.pem')  


#MyRSADecrypt('test2', RSACiphertext, Ciphertext, IV, tag, ext, 'privateKey2.pem')
      
      
      
      
      