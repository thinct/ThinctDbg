import os
import numpy as np
import struct

def float_to_hex(f):
    return hex(struct.unpack('<I', struct.pack('<f', f))[0])

float_to_hex(17.5)    # Output: '0x418c0000'

def double_to_hex(f):
    return hex(struct.unpack('<Q', struct.pack('<d', f))[0])

double_to_hex(17.5)   # Output: '0x4031800000000000L'

def hex_to_float(hFmt):
    return struct.unpack('!f', bytes.fromhex(hFmt))[0]

hex_to_float('41700000')

def hex_to_double(hFmt):
    return struct.unpack('!d', bytes.fromhex(hFmt))[0]

hex_to_double("402e000000000000")

def hex_to_number(h):
    hexStrLen = len(hex(h)[2:])
    if hexStrLen==8:
        print("float  : ", hex_to_float(hex(h)[2:]))

    if hexStrLen==16:
        print("double : ", hex_to_double(hex(h)[2:]))

    if hexStrLen==4:
        print("int16  : ", np.int16(h))

    if hexStrLen==8:
        print("int32  : ", np.int32(h))

    if hexStrLen==16:
        print("int64  : ", np.int64(h))

    if hexStrLen==8:
        print("uint16 : ", np.uint16(h))

    print("uint64 : ", np.uint64(h))
    
print('number parse...')
hex_to_number(0x41700000)
#hex_to_number(0x402e000000000000)
#hex_to_number(0xFFFC)
#hex_to_number(0x0024)