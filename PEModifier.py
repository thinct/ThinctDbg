import sys
import re
import time
import json
import gflags
import pefile
from enum import Enum

gflags.DEFINE_string('PEPath',         "",   'PE file path')
gflags.DEFINE_boolean('EnableASLR', False,   'Disable ASLR')

def modify_dll_characteristics(file_path, EnableASLR):
    # 打开 PE 文件
    pe = pefile.PE(file_path, fast_load=True)
 
    # 获取当前的 DLLCharacteristics
    current_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    if EnableASLR is True:
        current_characteristics |= (1<<6)
    else: 
        current_characteristics &= ~(1<<6)
 
    # 修改 DLLCharacteristics
    print("pe.OPTIONAL_HEADER.DllCharacteristics:0x{:0>8X}".format(pe.OPTIONAL_HEADER.DllCharacteristics))
    pe.OPTIONAL_HEADER.DllCharacteristics = current_characteristics
    print("pe.OPTIONAL_HEADER.DllCharacteristics:0x{:0>8X}".format(pe.OPTIONAL_HEADER.DllCharacteristics))
     
    # 保存修改后的 PE 文件
    pe.write(filename=file_path)
 

if __name__ == "__main__":
    print('args count:', len(sys.argv))
    print('argv list:', str(sys.argv))
    if len(sys.argv)<2:
        print("please input disasm addr range")
        exit()

    # Parse command line arguments
    gflags.FLAGS(sys.argv)
    PEPath     = gflags.FLAGS.PEPath
    EnableASLR = gflags.FLAGS.EnableASLR

    # 指定 PE 文件路径和要设置的 DLLCharacteristics
    file_path = PEPath

    # 执行修改
    modify_dll_characteristics(file_path, EnableASLR)