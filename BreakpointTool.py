import sys
import re
from LyScript32 import MyDebug
import gflags


# python BreakpointTool.py --E 0x403000 --RegExp "push ebp[\s\S]*?push edi[\s\S].*?push esi[\s\S]"
# python BreakpointTool.py --E 0x403000 --Step 100
# python BreakpointTool.py --S 0x400000 --E 0x410000 --Step 100

gflags.DEFINE_integer('S',     0x0, 'start point')
gflags.DEFINE_integer('E',     0x0, 'end point')
gflags.DEFINE_integer('Step',  0x0, 'break point step')
gflags.DEFINE_string('RegExp', "", 'regular expression')


    
# 得到机器码
def GetHexCode(dbg,address):
    ref_bytes = []
    # 首先得到反汇编指令,然后得到该指令的长度
    asm_len = dbg.assemble_code_size( dbg.get_disasm_one_code(address) )
    # 循环得到每个机器码
    for index in range(0,asm_len):
        ref_bytes.append(dbg.read_memory_byte(address))
        address = address + 1
    return ref_bytes    

if __name__ == "__main__":
    print('args count:', len(sys.argv))
    print('argv list:', str(sys.argv))
    if len(sys.argv)<2:
        print("please input disasm addr range")
        exit()

    # 解析命令行参数
    gflags.FLAGS(sys.argv)
    print(gflags.FLAGS.S)
    FuncStartIP  = gflags.FLAGS.S
    FuncEndIP    = gflags.FLAGS.E
    Step         = gflags.FLAGS.Step
    RegExp       = gflags.FLAGS.RegExp

    AddrsFromIDAFuncs = []
    with open('C:/DisasmSet', 'r', encoding='utf-8') as file:
        AddrsFromIDAFuncItem = []
        while line := file.readline():
            # print(line)
            # ['0X00401000', '', '', '', 'PUSH', '', '', '', 'EBP\n']
            if ";--------" in line:
                AddrsFromIDAFuncs += [AddrsFromIDAFuncItem]
                AddrsFromIDAFuncItem = []
                continue
            lineItems = line.upper().split(' ')
            addrValue = int(lineItems[0],16)
            AddrsFromIDAFuncItem += [(addrValue, lineItems[4])]
            
    print("IDA functions group count : ", len(AddrsFromIDAFuncs))
    
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))
    
    # 比对相同地址Dbg和IDA反汇编代码是否是一致的，只对一致的代码进行下断点处理
    addressNearFuncEntry = []
    addrIndex       = 0
    dbg.enable_commu_sync_time(False)
    for funcItem in AddrsFromIDAFuncs:
        for insAsmLine in funcItem:
            IPAddr,DisInsAsmOpr = insAsmLine
            print(type(IPAddr))
            print(IPAddr)
            disasm  = dbg.get_disasm_one_code(IPAddr).upper()
            if DisInsAsmOpr not in disasm:
                print("0x{:0>8X} {}".format(IPAddr, disasm.upper()))
                print("0x{:0>8X} {}".format(IPAddr, DisInsAsmOpr))
                print("not matched.")
            else:
                addressNearFuncEntry += [IPAddr]
                print("matched")
                break

    print("BP readly!")
    print("--------------------------------------------\n")
    

    dbg.enable_commu_sync_time(True)
    for address in addressNearFuncEntry:
        print("Set BP 0x{:0>8X}".format(address))
        dbg.set_breakpoint(address)

    print("BP finished\n")
    print("--------------------------------------------\n")

    while True:
        in_key = input("Continue to run for record brokenpoint of via address...\n").upper()
        if in_key == 'yes'.upper():
            break
        elif in_key == 'no'.upper():
            print("Finished")
            exit()
  
    dbg.enable_commu_sync_time(True)
    addressViaBreakStep = []
    while True:
        dbg.set_debug("run")
        eip = dbg.get_register("eip")
        ExMsg = ""
        with open('ExternMsg.txt', 'r') as file:
            ExMsg = file.readline().strip().upper()
            if ExMsg == 'Reset'.strip().upper():
                addressViaBreakStep = []
                input("reset the via bp, you can enter other cmd, then continue parse...\n")
                ExMsg = file.readline().strip().upper()
            if ExMsg == 'Running'.strip().upper():
                print("running while DelViaBP 0x{:0>8X}".format(eip))
                dbg.delete_breakpoint(eip)
                addressViaBreakStep += [eip]
            if ExMsg == 'over'.strip().upper():
                print("task over!!!")
                break
                
    in_key = input("resume the deleted BP after delete unused bp of x64dbg window.\n").strip().upper()
    if in_key == 'yes'.upper():
        for deletedEip in addressViaBreakStep:
            dbg.set_breakpoint(deletedEip)
    print("--------------------------------------------\n")
    
    dbg.close()
    print("Finished!")