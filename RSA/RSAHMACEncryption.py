import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA



#module to encrypt a string value


def MyfileEncryptMAC(filepath,Encryptionkey, HMACKey):

   
    with open(filepath, 'rb') as f:

        data = f.read()

        

    encryptedFileData = MyEncrypt(data,Encryptionkey, HMACKey)

    ext = os.path.splitext(filepath)[1]

    encryptedFileData += (Encryptionkey, HMACKey, ext)

    

    filepath = input("Enter a file path to store the encrypted data: ")

    result = open(filepath + ext, 'wb')

    result.write(encryptedFileData[0])

    

    return encryptedFileData, encryptionkey, HMACKey

def MyfileDecrypt(filepath, IV, tag, EncryptionKey,HMACKey, ext):

    with open(filepath, 'rb') as f:

        data = f.read()

        

    filePath = input("Enter a file path to store the decrypted data: ")

        

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




def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
     #Call MyfileEncrypt
     Encryptionkey = os.urandom(32)
     HMACKey = os.urandom(32)
     ciphertext, iv, tag, encryptionKey, HMACKey, ext = MyfileEncryptMAC(filepath,Encryptionkey, HMACKey)
     
     msg = str(Encryptionkey) +  str(HMACKey)
     
     if os.path.exists(RSA_Publickey_filepath):
         key = RSA.importKey(open(RSA_Publickey_filepath).read())
         RSACipher = PKCS1_OAEP.new(key)
         RSACiphertext = RSACipher.encrypt(msg)
     else: 
        f = open(RSA_Publickey_filepath,'w+')
        key = RSA.importKey(open(RSA_Publickey_filepath).write())
        RSACipher = PKCS1_OAEP.new(key)
        RSACiphertext = RSACipher.encrypt(msg)
     return RSACipher,cipertext, iv, tag, ext
     
     


def MyRSADecrypt(filepath,RSACiphertext, Cipher, IV, tag, ext, RSA_Privatekey_filepath)
    
     key = RSA.importKey(open(RSA_Privatekey_filepath).read())
     RSACipher = PKCS1_OAEP.new(key)
     message = cipher.decrypt(RSACiphertext)
      
    Encryptionkey = message[0:255]
    HMACKey = message[256:511]   
    
    MyfileDecrypt(filepath+ext, Cipher, IV, tag, Encryptionkey, HMACKey,ext)
    
    
      
      
      
      
      
      
      
      
      
      
