#################
# Crypto Week 3 #
#################

import os
import sys
import binascii
from Crypto.Hash import SHA256 

# chunck of 1024 bytes
CHUNKSIZE = 1024
# AES block size of 64 bytes (512 bits)
AES_BS = 64 

class HashChunkFile (object):
    """Breaks the file into 1KB blocks (1024 bytes)"""

    def __init__(self, fileName):
        """Initiate an object to break a file into chunks"""
        self.fileName = fileName
       
    def getHash (self, size = CHUNKSIZE):
        """Get the Hash of chunks from file"""
        try:
            f = open(self.fileName, mode='rb')
        except:
            print("ERROR: File ", fileName, "does not exist here ", os.getcwd ())
            sys.exit()
        
        # cursor at the end of file (seek relative to the file's end)
        f.seek(0,2)
        # size of file according to the last position of the cursor
        size = f.tell()

        nbBlocks = size // CHUNKSIZE
        # if last block is less than 1024 bytes, it is at cursor-position nbBlocks
        # otherwise, the last block is at cursor-position nbBlocks-1
        if(size % CHUNKSIZE == 0):
            nbBlocks -= 1
            
        h_previous_chunk = b""
        for i in range (nbBlocks, -1, -1):
            f.seek(i * CHUNKSIZE, 0)
            chunk = f.read(CHUNKSIZE)
            chunk = chunk + h_previous_chunk
            h = SHA256.new()
            h.update(chunk)
            h_previous_chunk = h.digest()
    
        # close file
        f.close()

        return (binascii.hexlify(h_previous_chunk))
           

########
# Main #
########
if __name__ == '__main__':
    chunkFileBreaker = HashChunkFile("6 - 1 - Introduction (11 min).mp4")
    hashCode = chunkFileBreaker.getHash()
    print("Your hash is ")
    print(hashCode)
    
                    
                    
                    
