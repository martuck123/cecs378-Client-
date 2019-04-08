"# cecs378-Client-" 
"# cecs378-Client-" 
"# cecs378-Client-" 

In this project you will use and modify the module you developed previously (File Encryption). You'll also use the OS package as well as JSON package.

Step 1:

Next, you will a script that looks for a pair of RSA Public and private key (using a CONSTANT file path; PEM format). If the files do not exist (use OS package) then generate the RSA public and private key (2048 bits length) using the same constant file path.

Step 2:

You are asked to write a method as below:

(RSACipher, C, IV, tag, ext)= MyRSAEncrypt(filepath, RSA_Publickey_filepath):

In this method, you first call MyfileEncryptMAC (filepath) which will return (C, IV, tag, Enckey, HMACKey, ext). You then will initialize an RSA public key encryption object and load pem publickey from the RSA_publickey_filepath. Lastly, you encrypt the key variable ("key"= EncKey+ HMACKey (concatenated)) using the RSA publickey in OAEP padding mode. The result will be RSACipher. You then return (RSACipher, C, IV, ext). Remember to do the inverse (MyRSADecrypt (RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath)) which does the exactly inverse of the above and generate the decrypted file using your previous decryption methods.

Step 3:

You can use the OS package to retrieve the current working directory. Then you can get a list of all files in this directory. For each file, encrypt them using MyRSAEncrypt from your new FileEncryptMAC module. Do this in a loop for all files (make sure you do not encrypt the RSA Private Key file). For every file that is encrypted, store the encrypted file as a JSON file. The attributes you have for each file are 'RSACipher', 'C', 'IV', 'tag' and 'ext'. The values are from MyRSAEncrypt method. Once the JSON fire is written (use json.dump() with file.write() methods) into a JSON file then you can remove the plaintext file (use os.remove() method). Note that you need to encode/decode your data before writing them into a JSON file.

Make sure then you can traverse thru all files within all sub-directories of a current working directory.  Encrypt all such files (either recursive execution or os.walk as an example).

Note: DO NOT test your script on any valuable file. It will be your responsibility if you lose any important data to you.

Step 4:

Using Pyinstaller or Py2exe create an executable file from your step 3.

Do NOT run the executable file on important folders. Only test on a designated python working directory. You are responsible if you lose any important file.
