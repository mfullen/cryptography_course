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
    enc = cipher_text_enc[16:]
    print "IV:", iv

    print "CipherMessage: " , len(enc)
    padded_plaintext = pad(plain_text).encode("hex")
    padded_injection = pad(injection_message).encode("hex")
    print "Padded Injection" , padded_injection.decode("hex")
    
    hex_xor_padded = hex_str_xor(padded_injection, padded_plaintext).encode("hex")
    print "PlainTextPadded XOR Injection Padded", hex_xor_padded
    
    iv_prime = hex_str_xor(iv.encode("hex"), hex_xor_padded).encode("hex")
    
    print "tampered IV HEX", iv_prime
    print "original cipher", cipher_text_hex
    tampered_cipher = iv_prime + enc.encode("hex")
    print "Tampered Cipher", tampered_cipher
    
    if (tampered_cipher) == "20814804c1767293bd9f1d9cab3bc3e750617920426f62203530302404040404":
        print "Wrong Answer (1st Try)", "20814804c1767293bd9f1d9cab3bc3e750617920426f62203530302404040404"
    elif (cipher_text_hex == tampered_cipher):
        print "Wrong Answer: Can't be equal to the original cipher"

if __name__ == '__main__':
    #cbc encryption with random IV using AES as the underlying block cipher
    #need to decrypt to "Pay Bob 500$"
    print len("20814804c1767293b99f1d9cab3bc3e7".decode("hex"))
    print len("ac1e37bfb15599e5f40eef805488281d".decode("hex"))
    print "========================Question 1: Injection  IV Attack==================="
    question_1_injection("20814804c1767293b99f1d9cab3bc3e7ac1e37bfb15599e5f40eef805488281d", "Pay Bob 100$", "Pay Bob 500$")
    