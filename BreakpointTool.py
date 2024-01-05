import sys
import re
from LyScript32 import MyDebug
import gflags


# python BreakpointTool.py --E 0x403000 --RegExp "push ebp[\s\S]*?push edi[\s\S].*?push esi[\s\S]"
# python BreakpointTool.py --E 0x403000 --Step 100
# python BreakpointTool.py --S 0x400000 --E 0x410000 --Step 100

gflags.DEFINE_integer('S',              0x0, 'start point')
gflags.DEFINE_integer('E',              0x0, 'end point')
gflags.DEFINE_integer('Step',           0x0, 'break point step')
gflags.DEFINE_string('RegExp',           "", 'regular expression')


    
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

    AddrsFromIDA        = []
    AddrsFromIDAWithOpr = {}
    with open('C:/DisasmSet', 'r', encoding='utf-8') as file:
        while line := file.readline():
            # print(line)
            # ['0X00401000', '', '', '', 'PUSH', '', '', '', 'EBP\n']
            lineItems = line.upper().split(' ')
            addrValue = int(lineItems[0],16)
            AddrsFromIDA += [addrValue]
            AddrsFromIDAWithOpr[addrValue] = lineItems[4]
            # print(AddrsFromIDA)
            # print(AddrsFromIDAWithOpr)
        
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))
    
    # 比对相同地址Dbg和IDA反汇编代码是否是一致的，只对一致的代码进行下断点处理
    addressWithStep = []
    addrIndex       = 0
    dbg.enable_commu_sync_time(False)
    for i in range(len(AddrsFromIDA)):
        IPAddr = AddrsFromIDA[i]
        disasm  = dbg.get_disasm_one_code(IPAddr).upper()
        if AddrsFromIDAWithOpr[IPAddr] not in disasm:
            print("0x{:0>8X} {}".format(IPAddr, disasm.upper()))
            print("0x{:0>8X} {}".format(IPAddr, AddrsFromIDAWithOpr[IPAddr]))
            print("not matched.")
        else:
            print("matched")
            if Step>0:
                addrIndex+=1
                if addrIndex % Step != 0:
                    continue
                print("0x{:0>8X} {}".format(IPAddr, disasm.upper()))
                addressWithStep += [IPAddr]
                # 跳过step条指令
                i += Step
    
    print("BP readly!")
    print("--------------------------------------------\n")
    
    #提取所有指令地址，然后按照步长设置断点
    if Step>0:
        dbg.enable_commu_sync_time(True)
        # 打印提取的地址部分
        for address in addressWithStep:
            print("Set BP 0x{:0>8X}".format(address))
            dbg.set_breakpoint(address)

    print("BP finished\n")
    print("--------------------------------------------\n")

    while True:
        in_key = input("Continue to run for record brokenpoint of via address...\n").upper()
        if ExMsg == 'yes'.upper():
            break
        if ExMsg == 'no'.upper():
            print("Finished")
            exit()
  
    addressViaBreakStep = []
    addressViaBreakRepetStep = []
    while True:
        dbg.set_debug("run")
        ExMsg = ""
        with open('ExternMsg.txt', 'r') as file:
            ExMsg = file.readline().strip().upper()
            with open('ExternMsg.txt', 'w') as f:
                pass
            if ExMsg != '':
                input('wait a moment...')
            if ExMsg == "Reset".upper():
                addressViaBreakStep = []
        if ExMsg == "Break".upper():
            break

        eip = dbg.get_register("eip")
        if eip in addressViaBreakStep:
            addressViaBreakRepetStep += [eip]
            continue
        if eip == 0x0:
            break
        print("0x{:0>8X}".format(eip))
        addressViaBreakStep += [eip]
        
    print(addressViaBreakStep)
    
    while True:
        eip = dbg.get_register("eip")
        in_key = input("Continue to delete invalid breakpoint...\n").upper()
        if in_key.strip() != "":
            if in_key == "yes".upper() or in_key == "Y".upper():
                break

    for breakStep in addressWithStep:
        if breakStep not in addressViaBreakStep:
            print("delete breakpoint 0x{:0>8X}".format(breakStep))
            dbg.delete_breakpoint(breakStep)
    
    print("--------------------------------------------\n")
    for repetItem in addressViaBreakRepetStep:
        addrValue = repetItem
        print("repet addr: 0x{:0>8X}\n".format(addrValue))
    
    dbg.close()
    print("Finished!")