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

    AddrsFromIDA = []
    with open('C:/InsAddress', 'r') as file:
        while line := file.readline():
            AddrsFromIDA += [int(line,16)]
        
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))
    dbg.enable_commu_sync_time(True)
    
    currentRIP = FuncStartIP
        
    printFormatIndex = 0
    DisasmFlows = ''    
    while True:
        dbg.enable_commu_sync_time(False)
        if currentRIP+1 > FuncEndIP:
            break
        
        disasm  = dbg.get_disasm_one_code(currentRIP)
        ref = GetHexCode(dbg, currentRIP)
        
        if disasm == "int3":
            currentRIP = currentRIP + len(ref)
            continue
        if len(ref)==2:
            if (ref[0] == 0 and ref[1] == 0):
                currentRIP = currentRIP + len(ref)
                continue
        if len(ref) == 0:
            currentRIP = currentRIP + 1
            continue
        if '?' in disasm:
            currentRIP = currentRIP + len(ref)
            continue
        currentRIP = currentRIP + len(ref)
        
        DisasmFlows = DisasmFlows + "0x{:0>8X}    {}\n".format(currentRIP, disasm)
        
    print("DisasmFlows:\n{}".format(DisasmFlows))

    #提取所有指令地址，然后按照步长设置断点
    addressWithStep = []
    if Step>0:
        dbg.enable_commu_sync_time(True)
        # 使用splitlines()方法将文本拆分成行，并遍历每一行提取地址部分
        addresses = [line.split()[0] for line in DisasmFlows.splitlines() if line.strip()]
        # 打印提取的地址部分
        addrIndex = 0
        for address in addresses:
            addrIndex+=1
            addrValue = int(address, 16)
            if addrValue not in AddrsFromIDA:
                continue
            if addrIndex % Step != 0:
                continue
            print("BP {}".format(address))
            dbg.set_breakpoint(addrValue)
            addressWithStep += [address]

    if RegExp is not '':
        dbg.enable_commu_sync_time(True)
        #pattern = r"(0x[0-9A-F]{8})\s*?push ebp[\s\S]*?push edi[\s\S]*?push esi"
        #pattern = r"(0x[0-9A-F]{8})\s*?" + r"add[\s\S]*?add[\s\S]*?"
        pattern = r"(0x[0-9A-F]{8})\s*?" + RegExp
        print(pattern)
        matches = re.findall(pattern, DisasmFlows, re.MULTILINE)
        # Print the matches and their respective addresses
        for instruction in matches:
            print(f"Instruction:\n {instruction}")
            dbg.set_breakpoint(int(instruction, 16))

    addressViaBreakStep = []
    addressViaBreakRepetStep = []
    while True:
        dbg.set_debug("run")
        with open('ExternMsg.txt', 'r') as file:
            ExMsg = file.readline().strip().upper()
            if ExMsg is not '':
                input('wait a moment...')
            if ExMsg == "Reset".upper():
                addressViaBreakStep = []
            
            with open('ExternMsg.txt', 'w') as f:
                pass  
        eip = dbg.get_register("eip")
        if eip in addressViaBreakStep:
            addressViaBreakRepetStep += [eip]
            continue
        if eip == 0x0:
            break
        print("0x{:0>8X}".format(eip))
        addressViaBreakStep += [eip]
        
    print(addressViaBreakStep)
    input('wait a momentAAA...')
    
    while True:
        eip = dbg.get_register("eip")
        in_key = input("Continue to delete invalid breakpoint...\n").upper()
        if in_key.strip() != "":
            if in_key == "yes".upper() or in_key == "Y".upper():
                break

    for breakStep in addressWithStep:
        addrValue = int(breakStep, 16)
        if addrValue not in addressViaBreakStep:
            print("delete breakpoint 0x{:0>8X}".format(addrValue))
            dbg.delete_breakpoint(addrValue)
    
    print("--------------------------------------------\n")
    for repetItem in addressViaBreakRepetStep:
        addrValue = repetItem
        print("repet addr: 0x{:0>8X}\n".format(addrValue))
    
    with open("DisasmFlows.asm", "w") as f:
        f.write(DisasmFlows)
    
    dbg.close()
    print("Finished!")