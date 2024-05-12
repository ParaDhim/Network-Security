#PROJECT-1 
#CONTRIBUTORS- AEKANSH KATHUNIA(2021127) AND PARAS DHIMAN(2021482)


import hashlib

def md5_hash(input_string):
    md5 = hashlib.md5()
    md5.update(input_string.encode('utf-8'))
    hshd=md5.hexdigest()
    hsh=""
    for i in hshd:
        if i.isnumeric():
            hsh+=chr(ord('a')+int(i))
        else:
            hsh+=chr(10+ord(i))
    return hsh

def check_pi(input_string):
    if(len(input_string)<=32):
        return False
    ot=input_string[:len(input_string)-32]
    hsh=input_string[-32:]
    return md5_hash(ot)==hsh

def encrypt(plain_text, key):
    cipher_text = ""
    key_length = len(key)

    for i in range(len(plain_text)):
        c = plain_text[i]
        key_char = key[i % key_length]
        cipher_text+=chr(ord('a')+((ord(c)-ord('a'))+(ord(key_char)-ord('a')))%26)

    return cipher_text

def decrypt(cipher_text, key):
    plain_text = ""
    key_length = len(key)

    for i in range(len(cipher_text)):
        c = cipher_text[i]
        key_char = key[i % key_length]
        plain_text+=chr(ord('a')+((ord(c)-ord('a'))-(ord(key_char)-ord('a')))%26)

    return plain_text

def brute_force(lst):
    for key1 in range(26):
        for key2 in range(26):
            for key3 in range(26):
                for key4 in range(26):
                    key = ''.join([chr(ord('a') + k) for k in [key1, key2, key3, key4]])
                    if(all([check_pi(decrypt(ciphertext,key)) for ciphertext in lst])):
                        return key
    return "WKEY"
                    
    
    
ra='1127'
rb='1482'
key=""
seed='c'
for i in range(4):
    key+=chr(ord('a')+((ord(seed)-ord('a'))+(int(ra[i])+int(rb[i]))%3)%26)

text=["helloyouaredull","whatsup","takeachillpill","itsreallycold","slowandsteady"]
plaintext=[i+md5_hash(i) for i in text]
# print(check_pi(plaintext))
print("orignal text:")
print(text)
print("__________________________________________________________")
print("plain text:")
print(plaintext)
print("__________________________________________________________")
print("do they satisfy the property pi:")
print([check_pi(i) for i in plaintext])
print("__________________________________________________________")
e=[encrypt(i,key) for i in plaintext]
print("encrypted ciphertext :")
print(e)
print("__________________________________________________________")
d=[decrypt(i,key) for i in e]
print("decrypted ciphertext : ")
print(d)
print("__________________________________________________________")
# print(e)
# print(decrypt(e,key))
print("Brute forcing solution:")
print(key)
print(brute_force(e))