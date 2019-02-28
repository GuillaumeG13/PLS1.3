## SHA-256 library
## made by Guillaume Gay

import binascii

def bin_to_oct2(string_to_convert):
    return bin(int(string_to_convert, 2))[2:].zfill(8)

def rightshift(string_to_rst):
    st = list(string_to_rst)
    st = ['0'] + st
    st.pop(-1)
    return (''.join(st))

def rightrotate(string_to_rrt):
    st = list(string_to_rrt)
    st = [''.join(st[-1])] + st
    st.pop(-1)
    return (''.join(st))

def xor_strings(a, b):
    y = int(a, 2)^int(b,2)
    return (bin(y)[2:].zfill(len(a)))

def and_strings(a, b):
    y = int(a, 2)&int(b,2)
    return (bin(y)[2:].zfill(len(a)))

def or_strings(a, b):
    y = int(a, 2)|int(b,2)
    return (bin(y)[2:].zfill(len(a)))

def not_string(a):
    st = list(a)
    for i in range (0, len(a)):
        if (st[i] == '0'):
            st[i] = '1'
        elif (st[i] == '1'):
            st[i] = '0'
    return (''.join(st))

def ch(x, y, z):
    return (xor_strings(and_strings(x, y), and_strings(not_string(x), z)))

def maj(x, y, z):
    return (xor_strings(xor_strings(and_strings(x, y), and_strings(x, z)), and_strings(y, z)))

def n_rightrotate(string_to_rrt, n):
    res = string_to_rrt
    for i in range (0, n):
        res = rightrotate(res)
    return res

def n_rightshift(string_to_rst, n):
    res = string_to_rst
    for i in range (0, n):
        res = rightshift(res)
    return res

def Smaj0(x):
    return (xor_strings(xor_strings(n_rightrotate(x, 2), n_rightrotate(x, 13)), n_rightrotate(x, 22)))

def Smaj1(x):
    return (xor_strings(xor_strings(n_rightrotate(x, 6), n_rightrotate(x, 11)), n_rightrotate(x, 25)))

def Smin0(x):
    return (xor_strings(xor_strings(n_rightrotate(x, 7), n_rightrotate(x, 18)), n_rightshift(x, 3)))

def Smin1(x):
    return (xor_strings(xor_strings(n_rightrotate(x, 17), n_rightrotate(x, 19)), n_rightshift(x, 10)))

def addBinMod32(x, y):
    return bin(((int(x, 2) + int(y, 2)) %(2**32)))[2:].zfill(32)