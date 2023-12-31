from idaapi import *
import idautils
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
    info_str += f"Address Current      : 0x{current_address:X}\n"
    info_str += f"Address Segment Start: 0x{addrSegStart:X}\n"
    info_str += f"Address Segment End  : 0x{addrSegEnd:X}\n"

    # 将信息写入文件
    output_file_path = os.path.join(os.getcwd(), "binary_info.txt")
    with open(output_file_path, "w") as output_file:
        output_file.write(info_str)

    print(f"Information extracted and saved to: {output_file_path}")
    print(info_str)


def DisassembleRange(start_ea, end_ea):
    codes = []
    current_ea = start_ea
    while current_ea <= end_ea:
        disasm_line = GetDisasm(current_ea)
        disasm = "0x{:08X}: {}".format(current_ea, disasm_line)
        print(disasm)
        codes += [disasm]
        current_ea = NextHead(current_ea)
    return codes
    
def GenAllAssemblyAddresses():  
    insSet = []
    for function_ea in idautils.Functions():
        for ins in idautils.FuncItems(function_ea):
            if idaapi.isCode(idaapi.getFlags(ins)):
                cmd = idc.GetDisasm(ins)
                mnem = cmd.split(' ')[0]
                #print("0x{:0>8X}    {}\n".format(ins, mnem))
                print("0x{:0>8X}    {}\n".format(ins, cmd))
                insSet += [ins]
                
    with open("C:/InsAddress", "w") as f:
        for item in insSet:
            f.write("0x{:0>8X}".format(item)+'\n')
  
#DisassembleRange(0x004079C0, 0x004079CC)
GenAllAssemblyAddresses()