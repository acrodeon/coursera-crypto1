###################################
# Crypto week4 CBC Padding Oracle #
###################################

import urllib.request
import sys
import binascii
TARGET = 'http://crypto-class.appspot.com/po?er='
IVCT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'

def myXor(a, b):
    return "".join([ hex(int(x, 16) ^ int(y, 16))[2:] for (x, y) in zip(a, b)])

#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        """q is "your ciphertext here" """
        # Create query URL
        target = TARGET + q
    
        # Send HTTP request to server
        req =  urllib.request.Request(target)        
        try:
            # Wait for response
            f = urllib.request.urlopen(req)
            #f = req.read()         
        except urllib.error.HTTPError as e:
            # Print response code
            #print ("We got: {0:d}".format(e.code))       
            if e.code == 404:
                return True # good padding
            return False # bad padding


#--------------------------------------------------------------
# launch CBC padding oracle attack block per block
#--------------------------------------------------------------
class CTbuilder(object):
    def __init__(self, ivct):
        """ivct is the hex encoded string IV||c[0]||c[1]..."""
        self.iv = ivct[0:32]
        self.c = []
        nbblocks = len(ivct) // 32
        for i in range(1,nbblocks,1):
            self.c.append(ivct[32*i:32*(i+1)])

    def attack(self, iv, c, isLastCT):
        """oracle attack of msg for block c with iv and a boolean if last block cipher with padding"""
        newIV = iv
        msg = ""
        pad = 0
        lastGuess = 0
        po = PaddingOracle()

        if (isLastCT):
            # Optimization to find out the padding in last block of original PT
            pad = 1
            hexPad = (hex(pad)[2:].zfill(2))*pad
            hexToAdd = myXor(newIV[30:], hexPad)
            guess = 0
            while (guess < 256):
                hexGuess = hex(guess)[2:].zfill(2)
                endIV = myXor(hexToAdd, hexGuess+msg) 
                query = newIV[:30] + endIV + c
                if(po.query(query)):
                    lastGuess = guess 
                guess = guess + 1
            # if lastGuess is 1 ou 16; we found the padding of last block
            if(lastGuess > 0 & lastGuess <= 16):
                hexLastGuess = hex(lastGuess)[2:].zfill(2)
                #msg end with the padding
                msg = hexLastGuess * lastGuess
                pad = lastGuess

        # we continue the search of bytes before the padding if any
        for i in range(32-2*lastGuess,0,-2):
            pad = pad + 1
            hexPad = (hex(pad)[2:].zfill(2))*pad
            hexToAdd = myXor(newIV[i-2:], hexPad)

            guess = 0
            while (guess < 256):
                hexGuess = hex(guess)[2:].zfill(2)
                endIV = myXor(hexToAdd, hexGuess+msg) 
                query = newIV[:i-2] + endIV + c
                if(po.query(query)):
                    msg = hexGuess+msg
                    break
                guess = guess + 1
        return msg

#--------------------------------------------------------------
# Main to revover the plaintext 
#--------------------------------------------------------------
if __name__ == "__main__":
    builder = CTbuilder (IVCT)
    m = []
    nbCipherBlocks = len(builder.c)
    
    # First cipher block with IV
    m.append(builder.attack(builder.iv, builder.c[0], nbCipherBlocks == 1))
    secret = binascii.unhexlify (m[0])
    print(secret)

    # Next cipher blocks with previous ciper block (as IV)
    for ctNb in range(1, len(builder.c), 1):
        m.append(builder.attack(builder.c[ctNb-1], builder.c[ctNb], nbCipherBlocks == ctNb+1))
        secret = secret + binascii.unhexlify (m[ctNb])
        print(secret)
        
    print("Your final plaintext is ")
    print(secret)
