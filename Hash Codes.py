import hashlib
from simplecrypt import encrypt, decrypt
value = "Peter : Hello"

def SHA256():
    result = hashlib.sha256(value.encode())
    print("SHA256 Encryted Data : ", result.hexdigest())
SHA256()

def MD5():
    result = hashlib.md5(value.encode())
    print("MD5 encryted data : ", result.hexdigest())
MD5()

message = "Peter : Hello"
hex_string = ''

def encrytion():
    global hex_string
    ciphercode = encrypt('AIM', message)
    hex_string = ciphercode.hex()
    print("Encrytion", hex_string)
    
def decrytion():
    global hex_string
    byte_str = bytes.fromhex(hex_string)
    original = decrypt('AIM', byte_str)
    final_message = original.decode("utf-8")
    print("Decryption", final_message)
    
encrytion()
decrytion()
