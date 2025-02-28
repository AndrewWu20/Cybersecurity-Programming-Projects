import sys
import math
from PrimeGenerator import *
from solve_pRoot import *
from BitVector import *

#Import stuff from RSA, follow directions and hints in pdf, and look at stuff online
class breakRSA():
    def __init__ (self , e) -> None :
        self . e = e
        self . n = None
        self . d = None
        self . p = None
        self . q = None

    # You are free to have other RSA class methods you deem necessary for your solution

    #Functions called in the main

    def encrypt(self, message, encrypt1, encrypt2, encrypt3, modulo):
        output = open(modulo, 'w')

        #Encryption 1
        bv = BitVector(filename = message)
        k1 = open(encrypt1, 'w')
        p, q = self.prime_generator()
        n1 = p * q
        output.write(str(n1))
        output.write("\n")
        self.encrypt_algo(bv, n1, k1)

        #Encryption 2
        bv = BitVector(filename = message)
        k2 = open(encrypt2, 'w')
        p, q = self.prime_generator()
        n2 = p * q
        output.write(str(n2))
        output.write("\n")
        self.encrypt_algo(bv, n2, k2)

        #Encryption 3
        bv = BitVector(filename = message)
        k3 = open(encrypt3, 'w')
        p, q = self.prime_generator()
        n3 = p * q
        output.write(str(n3))
        output.write("\n")
        self.encrypt_algo(bv, n3, k3)

            

    def cracked(self, encrypt1, encrypt2, encrypt3, modulo, cracked):
        input = open(modulo, 'r')
        output = open(cracked, 'w')     

        n1 = int(input.readline())                                  #Obtaining n1 and reading encrypt1 file
        bv_n1 = BitVector(intVal = n1)
        e1 = open(encrypt1, 'r')
        txt1 = e1.read()          
        txt1 = BitVector(hexstring = txt1)                                  

        n2 = int(input.readline())                                  #Obtaining n2 and reading encrypt2 file
        bv_n2 = BitVector(intVal = n2)
        e2 = open(encrypt2, 'r')
        txt2 = e2.read()
        txt2 = BitVector(hexstring = txt2)

        n3 = int(input.readline())                                  #Obtaining n3 and reading encrypt3 file
        bv_n3 = BitVector(intVal = n3)
        e3 = open(encrypt3, 'r')
        txt3 = e3.read()
        txt3 = BitVector(hexstring = txt3)
        
        
        n_all = n1 * n2 * n3                                        #Calculating N
        bv_p1 = BitVector(intVal = int(n2 * n3))                    #Calculating Ni
        bv_p2 = BitVector(intVal = int(n1 * n3))
        bv_p3 = BitVector(intVal = int(n1 * n2))
        pair = [bv_p1, bv_p2, bv_p3]
        bv_p1MI = bv_p1.multiplicative_inverse(bv_n1).int_val()     #Calculating MIs of Ni
        bv_p2MI = bv_p2.multiplicative_inverse(bv_n2).int_val()
        bv_p3MI = bv_p3.multiplicative_inverse(bv_n3).int_val()
        pair_MI = [bv_p1MI, bv_p2MI, bv_p3MI]

        
        block = int(len(txt1) // 256)                               #Read in blocks of 256 bits
        for element in range(block):
            bv_1 = txt1[256*element:256*(element+1)]                #Slice each input by 256 bits
            bv_2 = txt2[256*element:256*(element+1)]
            bv_3 = txt3[256*element:256*(element+1)]
            txt = [bv_1, bv_2, bv_3]
            sum = 0
            for j in range(len(pair)):                              #Summation calculation
                text = int(txt[j])
                curr_pair = int(pair[j])
                curr_pairMI = int(pair_MI[j])
                sum += text * curr_pair * curr_pairMI               #Calculate the summation
            sum = sum % n_all                                       #Summation mod N
            message = solve_pRoot(3, sum)                           #Calculate the cube root of sum, which is the message
            bv_message = BitVector(intVal = message, size = 128)    #Turn 256 bit bitvector into 128 bit bitvector
            output.write(bv_message.get_bitvector_in_ascii())

    #Written helper functions
        
    def prime_generator(self):
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
        return p, q

    def encrypt_algo ( self , bv, n, output ) -> None :
        while(bv.more_to_read):                                                 #Keep looping until nothing more to read
            block = bv.read_bits_from_file(128)
            if(block.size != 128):                                              #If the block size is not 128, pad it so the size is 128 bits
                block.pad_from_right(128 - block.size)
            modulus = pow(block.int_val(), self.e, n)                           #Calculate the modulus with the operation being block ^ e mod n
            bv_modulus = BitVector(intVal = modulus, size = 256)                #Make the modulus a bitvector size 256
            output.write(bv_modulus.get_bitvector_in_hex())                     #Write to output file
        output.close()

if __name__ == "__main__":
    cipher = breakRSA(e=3)
    if sys.argv[1] == "-e":
        cipher.encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif sys.argv[1] == "-c":
        cipher.cracked(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])  