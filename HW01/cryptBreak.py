from BitVector import *

def cryptBreak(ciphertextFile, key_bv):
    
    #Given a cipher text, the code conducts a brute force attack via testing keys in 
    # the range of 0 - 2^16 and then XORing bit blocks to decrypt the cipher text
    
    passphrase =  "Hopes and dreams of a million years"                         #(C)
    BLOCKSIZE = 16                                                              #(D)
    byte_num = BLOCKSIZE // 8                                                   #(E)

    # Create a bitvector from the ciphertext hex string:
    FILEIN = open(ciphertextFile)                                               #(J)
    encrypted_bv = BitVector( hexstring = FILEIN.read() )                       #(K)

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                  #(F)
    for i in range(0,len(passphrase) // byte_num):                              #(G)
        textstr = passphrase[i*byte_num:(i+1)*byte_num]                         #(H)
        bv_iv ^= BitVector( textstring = textstr )                              #(I)

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )                                    #(T)

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv                                            #(U)
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):                          #(V)
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]                          #(W)
        temp = bv.deep_copy()                                                   #(X)
        bv ^=  previous_decrypted_block                                         #(Y)
        previous_decrypted_block = temp                                         #(Z)
        bv ^=  key_bv                                                           #(a)
        msg_decrypted_bv += bv                                                  #(b)

    # Extract plaintext from the decrypted bitvector:    
    outputtext = msg_decrypted_bv.get_text_from_bitvector()                     #(c)
    return outputtext