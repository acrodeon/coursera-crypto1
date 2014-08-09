####################################
# Use of pyCrypto for AES CTR mode #
####################################

########################################
# binascii : for hexlify and unhexlify #
# -------------------------------------
# >>> binascii.unhexlify(b'08')
# b'\x08'
# >>> binascii.hexlify(b'08')
# b'3038'
# -------------------------------------
# Crypto.Cipher : for AES, Counter     #
########################################
import binascii
import sys
from Crypto.Cipher import AES
from Crypto.Util import Counter

#############
# constants #
#############
BS = AES.block_size

class AESCipher:
    def __init__( self, key ):
        """AES cipher that uses a string to be binascii.unhexlify() as a key"""
        self.key = binascii.unhexlify(key)  # or bytes.fromhex(key)
        
    def encrypt( self, iv, msg, mode=AES.MODE_CTR):
        """msg is the plaintext as a string to be encoded as UTF-8
           iv is the string of 32 digits and 16 bytes to be int in base 16
           mode by default AES.MODE_CBC"""
        raw = msg.encode("utf8")
        ctrValue = int(iv, 16)
        ctr = Counter.new(nbits=128, initial_value = ctrValue)
        cipher = AES.new( self.key, mode, counter=ctr )
        CT = cipher.encrypt( raw )
        # CT is converted from string (of 1 digit as 1 byte) to bytes
        CT = binascii.hexlify(CT)
        # iv is converted from string (of 2 digits as 1 byte) to bytes
        iv = binascii.unhexlify(iv)
        return iv + CT
    

    def decrypt( self, enc, mode=AES.MODE_CTR):
        """enc is the ciphertext with prepended IV to be binascii.unhexlify() before decryption"""
        enc = binascii.unhexlify(enc)
        iv = int.from_bytes(enc[:16], byteorder='big')
        ct = enc[16:]

        ### or
        ## iv = int(enc[:32], 16)
        ## ct = binascii.unhexlify(enc[32:])
        ##              
        
        ctr = Counter.new(nbits=128, initial_value = iv)
        
        cipher = AES.new(self.key, mode, counter=ctr )
        pt = cipher.decrypt(ct)
        print("In bytes mode ", pt)
        pt = pt.decode("utf8", 'ignore')
        print("In string mode ", pt)
        return pt

    
##################
# Main() to test #
##################
if __name__ == '__main__':
    
    mode = AES.MODE_CTR
    key = "36f18357be4dbd77f050515c73fcf9f2"
    ciphertext = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
    iv = ciphertext[:32]
    key=key[:32]
    decryptor = AESCipher(key)
    plaintext = decryptor.decrypt(ciphertext)
    print (plaintext) 

    recipherText = decryptor.encrypt(iv, plaintext)
    recipherText = binascii.hexlify(recipherText)
    print("ciphertext again : ", recipherText)
    secret = decryptor.decrypt (ciphertext)
    print ("Plaintext again : ", secret)

    print()
    print ("**********")
    print ("SECOND ...")
    print ("**********")
    print()

    key = "36f18357be4dbd77f050515c73fcf9f2"
    ciphertext = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";
    iv = ciphertext[:32]
    key=key[:32]
    decryptor = AESCipher(key)
    plaintext = decryptor.decrypt(ciphertext)
    print (plaintext) 

    recipherText = decryptor.encrypt(iv, plaintext)
    recipherText = binascii.hexlify(recipherText)
    print("ciphertext again : ", recipherText)
    secret = decryptor.decrypt (ciphertext)
    print ("Plaintext again : ", secret)
    
