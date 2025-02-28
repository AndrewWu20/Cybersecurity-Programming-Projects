import sys
import math
from PrimeGenerator import *
from BitVector import *

class RSA ():
    def __init__ (self , e) -> None :
        self . e = e
        self . n = None
        self . d = None
        self . p = None
        self . q = None
        if(sys.argv[1] != '-g'):
            p_file = open(sys.argv[3], 'r')
            q_file = open(sys.argv[4], 'r')
            self.p_num = int(p_file.readline())
            self.q_num = int(q_file.readline())

    # You are free to have other RSA class methods you deem necessary for your solution

    #Functions called in the main
    def prime_generator(self, p, q):
        outputp = open(p, "w")                                  #Open files to write to
        outputq = open(q, "w")
        prime_gen = PrimeGenerator(bits = 128)
        checker = 0
        while(checker == 0):                                    #Loop until random number conditions are satisfied
            checker = 1
            p = prime_gen.findPrime()                           #Create prime numbers p and q
            q = prime_gen.findPrime()
            p_msb = p & 11                                      #Isolate the MSB of both p and q
            q_msb = q & 11
            if((p_msb != 11) | (q_msb != 11) | (p == q) |       #If conditions are not met, continue looping
               (math.gcd(p - 1, self.e) != 1) | (math.gcd(q - 1, self.e) != 1)):
                checker = 0
        outputp.write(str(p))                                   #Write to output files
        outputq.write(str(q))
        outputp.close()
        outputq.close()

    def encrypt ( self , plaintext :str , ciphertext :str ) -> None :
        bv = BitVector(filename = plaintext)                                    #Create bitvector variable of plaintext
        output = open(ciphertext, 'w')
        n = self.p_num * self.q_num                                             #Compute n
        while(bv.more_to_read):                                                 #Keep looping until nothing more to read
            block = bv.read_bits_from_file(128)
            if(block.size != 128):                                              #If the block size is not 128, pad it so the size is 128 bits
                block.pad_from_right(128 - block.size)
            modulus = pow(block.int_val(), self.e, n)                           #Calculate the modulus with the operation being block ^ e mod n
            bv_modulus = BitVector(intVal = modulus, size = 256)                #Make the modulus a bitvector size 256
            output.write(bv_modulus.get_bitvector_in_hex())                     #Write to output file
        output.close()

    def decrypt ( self , ciphertext :str , recovered_plaintext :str ) -> None :
        input = open(ciphertext, 'r')                                               #Read input and write output
        output = open(recovered_plaintext, 'w')
        n = self.p_num * self.q_num                                                 #Calculate n
        totient = (self.p_num - 1) * (self.q_num - 1)                               #Calculate totient
        bv_e = BitVector(intVal = self.e)                                           #Convert e, p, q, and the totient to BitVectors
        bv_p = BitVector(intVal = self.p_num)
        bv_q = BitVector(intVal = self.q_num)
        bv_totient = BitVector(intVal = totient)
        d = bv_e.multiplicative_inverse(bv_totient).int_val()                       #Calculate d
        for counter in input:                                                       #Convert ciphertext from hex
            bv = BitVector(hexstring = counter)
        for element in range(0, len(bv) // 256):                                    #Read in block sizes of 256
            block = bv[256*element:256*(element+1)]                                 #Create blocks of size 256
            if(block._getsize() > 0):
                cipher = block.int_val()                                            #Computations are based of off CRT calculations in notes
                Vp = pow(cipher, d, self.p_num)                                     
                Vq = pow(cipher, d, self.q_num)
                Xp = self.q_num * bv_q.multiplicative_inverse(bv_p).int_val()
                Xq = self.p_num * bv_p.multiplicative_inverse(bv_q).int_val()
                decrypted = (Vp * Xp + Vq * Xq) % n
                bv_decrypted = BitVector(intVal = decrypted, size = 128)            #Convert decrypted into a BitVector size 128
                output.write(bv_decrypted.get_bitvector_in_ascii())                 #Write to output
        output.close()

if __name__ == "__main__":
    cipher = RSA(e=65537)
    if sys.argv[1] == "-g":
        cipher.prime_generator(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "-e":
        cipher.encrypt(plaintext = sys.argv[2], ciphertext = sys.argv[5])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext = sys.argv[2], recovered_plaintext = sys.argv[5])      