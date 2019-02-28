## SHA-256 implementation
## Wikipedia SHA256 : https://en.wikipedia.org/wiki/SHA-2
## test vectors : https://www.di-mgt.com.au/sha_testvectors.html
## made by Guillaume Gay

import binascii
from shalib import bin_to_oct2, ch, maj, Smaj0, Smaj1, Smin0, Smin1, addBinMod32

def sha256(string_to_hash):

    ## first 32 bits of the fractional parts of the square roots of the first 8 prime numbers
    H = [
    "6a09e667", "bb67ae85", "3c6ef372", "a54ff53a", "510e527f", "9b05688c", "1f83d9ab", "5be0cd19" ]

    ## Converting H into binary numbers
    for i in range (0, len(H)):
        H[i] = bin(int(H[i], 16))[2:].zfill(32)

    ## first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers
    K = [
   "428a2f98", "71374491", "b5c0fbcf", "e9b5dba5", "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
   "d807aa98", "12835b01", "243185be", "550c7dc3", "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
   "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc", "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
   "983e5152", "a831c66d", "b00327c8", "bf597fc7", "c6e00bf3", "d5a79147", "06ca6351", "14292967",
   "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13", "650a7354", "766a0abb", "81c2c92e", "92722c85",
   "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3", "d192e819", "d6990624", "f40e3585", "106aa070",
   "19a4c116", "1e376c08", "2748774c", "34b0bcb5", "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
   "748f82ee", "78a5636f", "84c87814", "8cc70208", "90befffa", "a4506ceb", "bef9a3f7", "c67178f2" ]
   
   ## Converting K into binary numbers
    for i in range (0, len(K)):
        K[i] = bin(int(K[i], 16))[2:].zfill(32)

    ## Padding the message
    binMsg = [bin(ord(c)) for c in string_to_hash]
    l = len(string_to_hash)*8
    z = (448 - l -1) % 512
    binMsg.append(bin(128))

    for i in range (0, ((z-7)//8)):
        binMsg.append(bin(0))

    for i in range (0, 64, 8):
        binMsg.append( '0b' + bin(int(str(l), 10))[2:].zfill(64)[i:i+8] )
    
    ## Parsing the message
    parsed = []
    for j in range (0,len(binMsg)-3, 4):
        parsed.append(bin_to_oct2(binMsg[j]) + bin_to_oct2(binMsg[j+1]) + bin_to_oct2(binMsg[j+2]) + bin_to_oct2(binMsg[j+3]))

    ## Hashing the message
    M = parsed

    # Split the message into 512 bits chunks
    for i in range (0, len(M)//16):
        w = []
        # Copy 32-bit chunck values into first 16 values of w
        for j in range (i*16, i*16 + 16):
            w.append(M[j])
        
        # Complete 16 to 64 w values
        for j in range (16, 64):
            s0 = Smin0(w[j-15])
            s1 = Smin1(w[j-2])
            w.append(addBinMod32(addBinMod32(addBinMod32(w[j-16], s0), w[j-7]), s1))

        (a, b, c, d, e, f, g, h) = (H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7])

        # Hashing
        for k in range (0, 64):
            S1 = Smaj1(e)
            myCh = ch(e, f, g)
            temp1 = addBinMod32(addBinMod32(addBinMod32(addBinMod32(h, S1), myCh), K[k]), w[k])
            S0 = Smaj0(a)
            myMaj = maj(a, b, c)
            temp2 = addBinMod32(S0, myMaj)

            h = g
            g = f
            f = e
            e = addBinMod32(d, temp1)
            d = c
            c = b
            b = a
            a = addBinMod32(temp1, temp2)
        
        H[0] = addBinMod32(H[0], a)
        H[1] = addBinMod32(H[1], b)
        H[2] = addBinMod32(H[2], c)
        H[3] = addBinMod32(H[3], d)
        H[4] = addBinMod32(H[4], e)
        H[5] = addBinMod32(H[5], f)
        H[6] = addBinMod32(H[6], g)
        H[7] = addBinMod32(H[7], h)

    # Converting the result into hexadecimal values
    resTab = [hex(int(H[0],2))[2:].zfill(8), hex(int(H[1],2))[2:].zfill(8), hex(int(H[2],2))[2:].zfill(8), hex(int(H[3],2))[2:].zfill(8), hex(int(H[4],2))[2:].zfill(8), hex(int(H[5],2))[2:].zfill(8), hex(int(H[6],2))[2:].zfill(8), hex(int(H[7],2))[2:].zfill(8)]

    res = ''
    for r in resTab:
        res += r

    return res