import sys
from BitVector import *

class AES():
    # class constructor - when creating an AES object , the
    # class ’s constructor is executed and instance variables
    # are initialized
    def __init__ ( self , keyfile :str ) -> None :
        self.AES_modulus = BitVector(bitstring='100011011')
        self.key = keyfile                                                      #Create a global variable for key
        self.subtable = self.gen_subbytes_table() 
        self.subtable_d = self.gen_subbytes_table_d()

    # encrypt - method performs AES encryption on the plaintext 
    # and writes the ciphertext to disk

    # Inputs : plaintext (str) - filename containing plaintext
    # ciphertext (str) - filename containing ciphertext
    # Return : void
    def encrypt ( self , plaintext :str , ciphertext :str ) -> None :           #Testing runtime ~6 minutes
        output = open(ciphertext, 'w')                                          
        bv = BitVector(filename = plaintext)                                    
        bv_key = BitVector(filename = self.key)                                 #Read keys via BitVector
        read_key = bv_key.read_bits_from_file(256)                              
        words = self.gen_key_schedule_256(read_key)                             #Generate key schedule from the keys
                
        while(bv.more_to_read):
            block = bv.read_bits_from_file(128)                                 #Read by block
            if(block.size != 128):                                              #If the block size is not 128, pad it so the size is 128 bits
                block.pad_from_right(128 - block.size)                          
            statearray = [[BitVector(size = 8) for x in range(4)] for x in range(4)]
            for i in range(4):                                                  #Slicing block to fill elements of statearray
                for j in range(4):
                    statearray[j][i] = block[32*i + 8*j:32*i + 8*j+8]
            statearray = self.addroundkey(statearray, words, 0)                 #Initial XOR with the first four words
            for round_num in range (1, 15):                                     #For rounds 1 - 13, input the state array through subbytes, 
                statearray = self.subbytes(statearray)                          #shiftrows, mixcolumns, and XOR the round key. With round 14,
                statearray = self.shiftrows(statearray)                         #omit the mixcolumn function
                if (round_num != 14):
                    statearray = self.mixcolumns(statearray)
                statearray = self.addroundkey(statearray, words, round_num)
            encrypted_bv = BitVector(size = 0)                                  
            for i in range(4):                                                  #Flatten statearray into one bitvector, called encrypted_bv
                for j in range(4):
                    encrypted_bv = encrypted_bv + statearray[j][i]
            output.write(encrypted_bv.get_bitvector_in_hex())                   #Write final output in hex

    #For each element in statearray, conduct the calculations given in the gen_subbytes_table function
    def subbytes(self, statearray):                                             
                                           
        for i in range(4):
            for j in range(4):
                statearray[i][j] = BitVector(intVal = self.subtable[statearray[i][j].intValue()], size = 8)
        return statearray

    #For each row in state array, shift row 2 one byte to the left, shift row 3 two bytes to the left, and shift row 4 three bytes to the left
    def shiftrows(self, statearray):                                            
        shifted_statearray = [[0 for x in range(4)] for x in range(4)]          
        for i in range(4):                                                      
            for j in range(4):
                shift = i
                if((shift + j) > 3):
                    shift = shift - 4
                shifted_statearray[i][j] = statearray[i][j + shift]
        return shifted_statearray

    #For each element of the state array, multiply the element by two, XOR that element with three times the next element in the column,
    #along with XORing the other two elements in the same column to obtain the replacement element
    def mixcolumns(self, statearray):
        mixed_statearray = [[0 for x in range(4)] for x in range(4)]
        for i in range(4):
            for j in range(4):
                if(i == 3):
                    mixed_statearray[i][j] = (statearray[3][j].gf_multiply_modular(BitVector(bitstring = "10"), self.AES_modulus, 8) ^
                                              statearray[0][j].gf_multiply_modular(BitVector(bitstring = "11"), self.AES_modulus, 8) ^
                                              statearray[1][j] ^ statearray[2][j])
                elif(i == 2):
                    mixed_statearray[i][j] = (statearray[2][j].gf_multiply_modular(BitVector(bitstring = "10"), self.AES_modulus, 8) ^
                                              statearray[3][j].gf_multiply_modular(BitVector(bitstring = "11"), self.AES_modulus, 8) ^
                                              statearray[0][j] ^ statearray[1][j])
                elif(i == 1):
                    mixed_statearray[i][j] = (statearray[1][j].gf_multiply_modular(BitVector(bitstring = "10"), self.AES_modulus, 8) ^
                                              statearray[2][j].gf_multiply_modular(BitVector(bitstring = "11"), self.AES_modulus, 8) ^
                                              statearray[3][j] ^ statearray[0][j])
                elif(i == 0):
                    mixed_statearray[i][j] = (statearray[0][j].gf_multiply_modular(BitVector(bitstring = "10"), self.AES_modulus, 8) ^
                                              statearray[1][j].gf_multiply_modular(BitVector(bitstring = "11"), self.AES_modulus, 8) ^
                                              statearray[2][j] ^ statearray[3][j])
        return mixed_statearray

    #For each element, XOR it with the corresponding byte in the key schedule
    def addroundkey(self, statearray, words, round_num):
        new_statearray = [[0 for x in range(4)] for x in range(4)]
        for i in range(4):
            for j in range(4):
                new_statearray[j][i] = statearray[j][i] ^ words[round_num * 4 + i][j*8:j*8+8]
        return new_statearray





    # decrypt - method performs AES decryption on the 
    # ciphertext and writes the recovered plaintext to disk
    
    # Inputs : ciphertext (str) - filename containing ciphertext
    # decrypted (str) - filename containing recovered plaintext
    # Return : void
    def decrypt ( self , ciphertext :str , decrypted :str ) -> None :           #Testing runtime ~6 minutes
        inputtext = (open(ciphertext, 'r')).read()                              #Open and read the encrypted file
        output = open(decrypted, 'w')
        blocks = int(len(inputtext) / 32)                                       #Create byte blocks
        bv_key = BitVector(filename = self.key)                                 #Read key via BitVector
        read_key = bv_key.read_bits_from_file(256)
        words = self.gen_key_schedule_256(read_key)                             #Generate key schedule from key

        for i in range(blocks):
            bitvec = BitVector(hexstring = inputtext[i * 32 + 0: i * 32 + 32])  #Create bitvec to get substrings by slicing indicies in encrypted file
            if bitvec._getsize() > 0:
                statearray = [[0 for x in range(4)] for x in range(4)]
                for i in range(4):                                              #Slice elements of bitvec to fill state array
                    for j in range(4):
                        statearray[j][i] = bitvec[32*i + 8*j:32*i + 8*j+8]
                statearray = self.addroundkey(statearray, words, 14)            #Initial XOR with the last four words  
                for round_num in range (13, -1, -1):                            #For rounds 14 - 2, push statearray through the functions invshiftrows, 
                    statearray = self.invshiftrows(statearray)                  #invsubbytes, addroundkey, and invmixcolumns, with the last round, round 1,
                    statearray = self.invsubbytes(statearray)                   #not involving the funciton invmixcolumns
                    statearray = self.addroundkey(statearray, words, round_num)
                    if (round_num != 0):
                        statearray = self.invmixcolumns(statearray)
                decrypted_bv = BitVector(size = 0)
                for i in range(4):                                              #Flatten statearray into one bit vector, named decrypted_bv
                    for j in range(4):
                        decrypted_bv = decrypted_bv + statearray[j][i]
                output.write(decrypted_bv.get_bitvector_in_ascii())             #Write the final output in ASCII

    #For each element in statearray, conduct the calculations given in the gen_subbytes_table_d function
    def invsubbytes(self, statearray):
        for i in range(4):
            for j in range(4):
                statearray[i][j] = BitVector(intVal = self.subtable_d[statearray[i][j].intValue()], size = 8)
        return statearray

    #For each row in state array, shift row 2 one byte to the right, shift row 3 two bytes to the right, and shift row 4 three bytes to the right
    def invshiftrows(self, statearray):
        shifted_statearray = [[0 for x in range(4)] for x in range(4)]
        for i in range(4):
            for j in range(4):
                shift = -i
                if((shift + i) < 0):
                    shift = shift + 4
                shifted_statearray[i][j] = statearray[i][j + shift]
        return shifted_statearray
                    
    #For each element of the state array, multiply the element by E, XOR that element with B times the next element in the column,
    #along with XORing the following two elements in the same column by D and 9 respectively to obtain the replacement element
    def invmixcolumns(self, statearray):
        mixed_statearray = [[0 for x in range(4)] for x in range(4)]
        for i in range(4):
            for j in range(4):
                if(i == 3):
                    mixed_statearray[i][j] = (statearray[3][j].gf_multiply_modular(BitVector(bitstring = "00001110"), self.AES_modulus, 8) ^
                                              statearray[0][j].gf_multiply_modular(BitVector(bitstring = "00001011"), self.AES_modulus, 8) ^
                                              statearray[1][j].gf_multiply_modular(BitVector(bitstring = "00001101"), self.AES_modulus, 8) ^ 
                                              statearray[2][j].gf_multiply_modular(BitVector(bitstring = "00001001"), self.AES_modulus, 8))
                elif(i == 2):
                    mixed_statearray[i][j] = (statearray[2][j].gf_multiply_modular(BitVector(bitstring = "00001110"), self.AES_modulus, 8) ^
                                              statearray[3][j].gf_multiply_modular(BitVector(bitstring = "00001011"), self.AES_modulus, 8) ^
                                              statearray[0][j].gf_multiply_modular(BitVector(bitstring = "00001101"), self.AES_modulus, 8) ^ 
                                              statearray[1][j].gf_multiply_modular(BitVector(bitstring = "00001001"), self.AES_modulus, 8))
                elif(i == 1):
                    mixed_statearray[i][j] = (statearray[1][j].gf_multiply_modular(BitVector(bitstring = "00001110"), self.AES_modulus, 8) ^
                                              statearray[2][j].gf_multiply_modular(BitVector(bitstring = "00001011"), self.AES_modulus, 8) ^
                                              statearray[3][j].gf_multiply_modular(BitVector(bitstring = "00001101"), self.AES_modulus, 8) ^ 
                                              statearray[0][j].gf_multiply_modular(BitVector(bitstring = "00001001"), self.AES_modulus, 8))
                elif(i == 0):
                    mixed_statearray[i][j] = (statearray[0][j].gf_multiply_modular(BitVector(bitstring = "00001110"), self.AES_modulus, 8) ^
                                              statearray[1][j].gf_multiply_modular(BitVector(bitstring = "00001011"), self.AES_modulus, 8) ^
                                              statearray[2][j].gf_multiply_modular(BitVector(bitstring = "00001101"), self.AES_modulus, 8) ^ 
                                              statearray[3][j].gf_multiply_modular(BitVector(bitstring = "00001001"), self.AES_modulus, 8))
        return mixed_statearray
    
    #Functions below were adapted from lecture material

    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.gen_subbytes_table()
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = 
                                    byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words
    
    def gee(self, keyword, round_constant, byte_sub_table):
        '''
        This is the g() function you see in Figure 4 of Lecture 8.
        '''
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant
    
    def gen_subbytes_table(self):
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable
    
    def gen_subbytes_table_d(self):
        invSubBytesTable = []
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            b = BitVector(intVal = i, size=8)
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            invSubBytesTable.append(int(b))
        return invSubBytesTable
    


if __name__ == "__main__":
    cipher = AES(keyfile = sys.argv[3])
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv [4])
    else:
        sys.exit(" Incorrect Command - Line Syntax ")
