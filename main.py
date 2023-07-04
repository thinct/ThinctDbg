import sys
import re
import time
import json
import gflags
from LyScript32 import MyDebug

# 定义标志
gflags.DEFINE_integer('S',             0x0, 'start point')
gflags.DEFINE_integer('E',             0x0, 'end point')
gflags.DEFINE_multi_int('Pause',       [], 'pause list')
gflags.DEFINE_multi_int('PauseOnce',   [], 'pause once list')
gflags.DEFINE_string('DisasmPart',   "",  'jmp')

    
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
    PauseIPs     = gflags.FLAGS.Pause
    PauseIPOnce  = gflags.FLAGS.PauseOnce
    DisasmPart   = gflags.FLAGS.DisasmPart
    if FuncStartIP >= FuncEndIP:
        print("the first is start addr and the second is end addr")
        exit()
        
        
    dbg          = MyDebug()
    connect_flag = dbg.connect()
    print("MyDebug connect status: {}".format(connect_flag))

    dbg.set_breakpoint(FuncStartIP)
    dbg.set_debug("run")   
    while True:
        dbg.enable_commu_sync_time(False)
        eip = dbg.get_register("eip")
        print("0x{:0>8X}  0x{:0>8X}".format(eip,FuncStartIP))
        # print("eip: 0x{:0>8X}".format(eip))
        # print("FuncStartIP: 0x{:0>8X}".format(FuncStartIP))
        if eip != FuncStartIP:
            dbg.enable_commu_sync_time(True)
            dbg.set_debug("run")
            in_key = input("The starting point has not been reached, so click any key to continue...")
            print(in_key)
            if in_key == "q" or in_key == "quit":
                print("quit!")
                exit()
            continue
        dbg.delete_breakpoint(FuncStartIP)
        break
        
    regsJson       = {"AddrFlow":[]}
    DisasmFlow     = ""
    DisasmFlowDirc = {}
    EIPSet         = []
    EIPGoToSet     = []
    while True:
        dbg.enable_commu_sync_time(False)
        eip = dbg.get_register("eip")
        if eip > FuncEndIP:
            break
        
        disasm  = dbg.get_disasm_one_code(eip)
        if eip in PauseIPs or (DisasmPart != "" and str(DisasmPart) in disasm):
            print("pause condition:", disasm, DisasmPart)
            in_key = input("This is a pause point where you can make changes to the x64dbg...")
        elif eip in PauseIPOnce:
            PauseIPOnce.remove(eip)
            print(PauseIPOnce)
            in_key = input("This is a pause point where you can make changes to the x64dbg...")
            
        
        if eip in EIPSet:
            dbg.enable_commu_sync_time(True)
            dbg.set_debug("StepOver")
            continue
        EIPSet += [eip]
         
        eax    = dbg.get_register("eax")
        ecx    = dbg.get_register("ecx")
        edx    = dbg.get_register("edx")
        ebx    = dbg.get_register("ebx")
        ebp    = dbg.get_register("ebp")
        esp    = dbg.get_register("esp")
        esi    = dbg.get_register("esi")
        edi    = dbg.get_register("edi")
        IPRegs = {"IP":"0x{:0>8X}".format(eip), "Disasm":"{}".format(disasm),"Regs":{"eax":"0x{:0>8X}".format(eax)\
        ,"ecx":"0x{:0>8X}".format(ecx),"edx":"0x{:0>8X}".format(edx),"ebx":"0x{:0>8X}".format(ebx),"ebp":"0x{:0>8X}".format(ebp)\
        ,"esp":"0x{:0>8X}".format(esp),"esi":"0x{:0>8X}".format(esi),"edi":"0x{:0>8X}".format(edi)}}
            
        disasmFlowItem = "/*0x{:0>8X}*/    {}".format(eip, disasm)
        print(disasmFlowItem)
        if disasm[0] == 'j': # jmp
            disasmFlowItem = ";" + disasmFlowItem
            if len(disasm) == 14:
                if int(str(disasm[4:14]), 16) < eip:
                    disasmFlowItem += ";GOTO BACK"
            if len(disasm) == 13:
                if int(str(disasm[3:13]), 16) < eip:
                    disasmFlowItem += ";GOTO BACK"
                
        elif disasm[0:4] == 'call' and disasm[5:7] == '0x':
            disasmFlowItem = 'mov eax, ' + disasm[5:15] + '\n' + "/*0x{:0>8X}*/    call eax".format(eip)
        #print(IPRegs)
        regsJson["AddrFlow"] += [IPRegs]
        DisasmFlowDirc[eip]  = disasmFlowItem
        DisasmFlow           += disasmFlowItem + "\n"
        print("currentRIP: 0x{:0>8X} eax: 0x{:0>8X}".format(eip, eax))
        
        dbg.enable_commu_sync_time(True)
        dbg.set_debug("StepOver")
   
        
    #print(regsJson)
    with open("AddrFlow.json", "w") as f:
        json.dump(regsJson["AddrFlow"], f, ensure_ascii=False, indent=2)
        
    with open("AddrFlowEasy.asm", "w") as f:
        f.write(DisasmFlow)
        
    LsDisasmFlowKeys = list(DisasmFlowDirc.items())
    LsDisasmFlowKeys.sort(key=lambda x:x[0],reverse=False)
    AddrJmpList = []
    disasmLineList = []
    for item in LsDisasmFlowKeys:
        disasmLine = item[1]
        if disasmLine[0] == ';':
            disasmLine = disasmLine[1:]
            pattern = r"\bj[a-z]+\b\s+(0x\w+)"
            match = re.search(pattern, disasmLine)
            if match:
                jmpAddr = match.group(1)
                AddrJmpList += [jmpAddr]
        disasmLineList += [disasmLine]
        # print(disasmLine)  
    print(AddrJmpList)  

    disasmWithLabel = []
    for  item in disasmLineList:
        if item[2:12] in AddrJmpList:
            item = "LABEL_{}:\n".format(item[2:12])+item
        disasmWithLabel += [item]
        
    with open("AddrFlowEasyWithJmp.asm", "w") as f:
        for item in disasmWithLabel:
            f.write(item+'\n')
     
    dbg.close()
    print("Finished!")