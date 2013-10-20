'''
Created on Oct 20, 2013

@author: mfullen
'''
from Crypto.Cipher import AES

BS = 16
unpad = lambda s : s[0:-ord(s[-1])]
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 

def hex_str_xor(A, B):
    res = ''
    for i in range(0,min(len(A),len(B)),2):
        res += chr(int(A[i]+A[i+1],16) ^ int(B[i]+B[i+1],16))
    return res

def question_1_injection(cipher_text_hex, plain_text, injection_message):
    cipher_text_enc = cipher_text_hex.decode("hex")
    iv = cipher_text_enc[:16]
    cipher_text_enc = cipher_text_enc[16:]
    
    padded_plaintext = pad(plain_text).encode("hex")
    padded_injection = pad(injection_message).encode("hex")
    print "Padded Injection" , padded_injection
    
    iv_xor_plain = hex_str_xor(iv.encode("hex"), padded_plaintext)
    tampered_iv_hex = hex_str_xor(iv_xor_plain.encode("hex"), padded_injection).encode("hex")
    print "tampered IV HEX", tampered_iv_hex
    tampered_cipher = tampered_iv_hex + padded_injection
    print "original cipher", cipher_text_hex
    print "Tampered Cipher",tampered_cipher

if __name__ == '__main__':
    #cbc encryption with random IV using AES as the underlying block cipher
    #need to decrypt to "Pay Bob 500$"
    print "========================Question 1: Injection  IV Attack==================="
    question_1_injection("20814804c1767293b99f1d9cab3bc3e7ac1e37bfb15599e5f40eef805488281d", "Pay Bob 100$", "Pay Bob 500$")
    
    