#################################################
# Use of pyCrypto for AES CBC mode and CTR mode #
#################################################

########################################
# binascii : for hexlify and unhexlify #
# -------------------------------------
# Return the binary data represented by the hexadecimal string 
# >>> binascii.unhexlify(b'08')
# b'\x08'
#
# Every byte of data is converted into the corresponding 2-digit hex representation
# >>> binascii.hexlify(b'08')
# b'3038'
# -------------------------------------
# Crypto.Cipher : for AES              #
########################################
import binascii
from Crypto.Cipher import AES

#############
# constants #
#############
BS = AES.block_size
# pad (PKCS5 padding scheme) plaintext s to multiple of BS
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
# unpad plaintext
unpad = lambda s : s[0:-ord(s[-1])]

class AESCipher:
    def __init__( self, key ):
        """AES cipher that uses a string to be binascii.unhexlify() as a key"""
        self.key = binascii.unhexlify(key) 
        
    def encrypt( self, iv, msg, mode=AES.MODE_CBC):
        """msg is the plaintext as a string to be padded and then encoded as UTF-8
           iv is the string of 32 digits and 16 bytes after binascii.unhexlify()
           mode by default AES.MODE_CBC"""
        msg = pad(msg)
        raw = msg.encode("utf8")
        iv = binascii.unhexlify(iv)
        raw = iv + raw
        #iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        CT = cipher.encrypt( raw )
        CT = binascii.hexlify(CT)
        return CT
    
    def decrypt( self, enc ):
        """enc is the ciphertext with prepended IV to be binascii.unhexlify() before decryption"""
        enc = binascii.unhexlify(enc)
        iv = enc[:16]
        enc= enc[16:]
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        pt = cipher.decrypt(enc)
        print("In bytes mode ", pt)
        print("In 2-digit hex mode ", binascii.hexlify(pt))
        pt = pt.decode("utf8", 'ignore')
        plaintext = unpad(pt)
        print("In string mode ", plaintext)
        return plaintext


##################
# Main() to test #
##################
if __name__ == '__main__':
    
    mode = AES.MODE_CBC
    key = "140b41b22a29beb4061bda66b6747e14"
    ciphertext = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
    iv = ciphertext[:32]
    key=key[:32]
    decryptor = AESCipher(key)
    plaintext = decryptor.decrypt(ciphertext)
    print (plaintext) 

    recipherText = decryptor.encrypt(iv, plaintext)
    print("ciphertext again : ", recipherText)
    secret = decryptor.decrypt (ciphertext)
    print ("Plaintext again : ", secret)

    print()
    print ("**********")
    print ("SECOND ...")
    print ("**********")
    print()
    
    ciphertext = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
    iv = ciphertext[:32]
    key=key[:32]
    decryptor = AESCipher(key)
    plaintext = decryptor.decrypt(ciphertext)
    print (plaintext) 

    recipherText = decryptor.encrypt(iv, plaintext)
    print("ciphertext again : ", recipherText)
    secret = decryptor.decrypt (ciphertext)
    print ("Plaintext again : ", secret)
    
