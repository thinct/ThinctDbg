import sys
import re
from LyScript32 import MyDebug
import gflags


# \BreakpointTool.py --ModuleName "MFCApplication1.exe"
# BreakpointTool.py --ModuleName "SearchDemo.exe" --E 0x403000 --RegExp "push ebp[\s\S]*?push edi[\s\S].*?push esi[\s\S]"

gflags.DEFINE_string('ModuleName',                  "", 'module name')
gflags.DEFINE_integer('S',                         0x0, 'start point')
gflags.DEFINE_integer('E',                         0x0, 'end point')
gflags.DEFINE_integer('Step',                      0x0, 'break point step')
gflags.DEFINE_string('RegExp',                      "", 'regular expression')

    
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
    ModuleName      = gflags.FLAGS.ModuleName
    FuncStartIP     = gflags.FLAGS.S
    FuncEndIP       = gflags.FLAGS.E
    Step            = gflags.FLAGS.Step
    RegExp          = gflags.FLAGS.RegExp
        
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    base = dbg.get_module_base(ModuleName)
    print("{} base: {:#X}".format(ModuleName, base))
    entry = dbg.get_local_module_entry()
    print("模块入口: {:#X}".format(dbg.get_local_module_entry()))
    
    currentRIP = base + 0x1000
    if FuncStartIP > 0x1000:
        currentRIP = FuncStartIP
    if FuncEndIP <= 0:
        FuncEndIP = entry
        
        
    DisasmFlows = ''    
    while True:
        dbg.enable_commu_sync_time(False)
        if currentRIP+1 > FuncEndIP:
            break
        ref = GetHexCode(dbg, currentRIP)
        
        disasm  = dbg.get_disasm_one_code(currentRIP)
        DisasmFlows = DisasmFlows + "0x{:0>8X}    {}\n".format(currentRIP, disasm)
        
        if len(ref) == 0:
            #print("----currentRIP: {:#X}".format(currentRIP))
            currentRIP = currentRIP + 1
            continue
        currentRIP = currentRIP + len(ref)
        
    print("DisasmFlows:\n{}".format(DisasmFlows))
    
    #提取所有指令地址，然后按照步长设置断点
    if Step>0:
        dbg.enable_commu_sync_time(True)
        # 使用splitlines()方法将文本拆分成行，并遍历每一行提取地址部分
        addresses = [line.split()[0] for line in DisasmFlows.splitlines() if line.strip()]
        # 打印提取的地址部分
        addrIndex = 0
        for address in addresses:
            if addrIndex % Step != 0:
                addrIndex+=1
                continue
            print("BP {}".format(address))
            dbg.set_breakpoint(int(address, 16))
            addrIndex+=1
    
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
    
    with open("DisasmFlows.asm", "w") as f:
        f.write(DisasmFlows)
    
    dbg.close()
    print("Finished!")