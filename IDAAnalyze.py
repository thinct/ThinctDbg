# 导入IDAPython模块
from idaapi import *
import os

def extract_information():
    # 获取二进制文件的基本信息
    # entry_point   = GetEntryPoint()  # 获取程序入口地址
    binary_name     = GetInputFile()  # 获取当前二进制文件的名称
    current_address = ScreenEA()
    addrSegStart    = SegStart(current_address)  
    addrSegEnd      = SegEnd(current_address)  

    # 创建要写入的信息字符串
    info_str =  f"Binary Name: {binary_name}\n"
    info_str += f"Address Segment Start: 0x{addrSegStart:X}\n"
    info_str += f"Address Segment End  : 0x{addrSegEnd:X}\n"

    # 将信息写入文件
    output_file_path = os.path.join(os.getcwd(), "binary_info.txt")
    with open(output_file_path, "w") as output_file:
        output_file.write(info_str)

    print(f"Information extracted and saved to: {output_file_path}")


