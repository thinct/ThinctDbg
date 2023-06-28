import sys
import time
import json
from LyScript32 import MyDebug

    
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("connect status: {}".format(connect_flag))

    print('args count:', len(sys.argv))
    print('argv list:', str(sys.argv))
    
    if len(sys.argv)<2:
        print("please input disasm addr range")
        exit()
    
    FuncStartIP = int(sys.argv[1], 16)
    FuncEndIP = int(sys.argv[2], 16)
    PauseIP = int(sys.argv[3], 16)
    if FuncStartIP > FuncEndIP:
        print("the first is start addr and the second is end addr")
        exit()
    
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
            in_key = input("press any key to continue...")
            print(in_key)
            if in_key == "q":
                print("quit!")
                exit()
            continue
        dbg.delete_breakpoint(FuncStartIP)
        break
        
    regsJson = {"AddrFlow":[]}
    DisasmFlow = ""
    DisasmFlowDirc = {}
    EIPSet = []
    EIPGoToSet = []
    while True:
        dbg.enable_commu_sync_time(False)
        eip = dbg.get_register("eip")
        if eip > FuncEndIP:
            break
        
        if PauseIP == eip:
            in_key = input("Pause...")
        
        if eip in EIPSet:
            dbg.enable_commu_sync_time(True)
            dbg.set_debug("StepOver")
            continue
        EIPSet += [eip]
         
        eax = dbg.get_register("eax")
        ecx = dbg.get_register("ecx")
        edx = dbg.get_register("edx")
        ebx = dbg.get_register("ebx")
        ebp = dbg.get_register("ebp")
        esp = dbg.get_register("esp")
        esi = dbg.get_register("esi")
        edi = dbg.get_register("edi")
        disasm = dbg.get_disasm_one_code(eip)
        IPRegs = {"IP":"0x{:0>8X}".format(eip), "Disasm":"{}".format(disasm),"Regs":{"eax":"0x{:0>8X}".format(eax)\
        ,"ecx":"0x{:0>8X}".format(ecx),"edx":"0x{:0>8X}".format(edx),"ebx":"0x{:0>8X}".format(ebx),"ebp":"0x{:0>8X}".format(ebp)\
        ,"esp":"0x{:0>8X}".format(esp),"esi":"0x{:0>8X}".format(esi),"edi":"0x{:0>8X}".format(edi)}}
            
        disasmFlowItem = "/*0x{:0>8X}*/    {}".format(eip, disasm)
        print(disasmFlowItem)
        if disasm[0] == 'j':
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
        DisasmFlowDirc[eip] = disasmFlowItem
        DisasmFlow += disasmFlowItem + "\n"
        print("currentRIP: 0x{:0>8X} eax: 0x{:0>8X}".format(eip, eax))
        
        dbg.enable_commu_sync_time(True)
        dbg.set_debug("StepOver")
   
        
    #print(regsJson)
    with open("AddrFlow.json", "w") as f:
        json.dump(regsJson["AddrFlow"], f, ensure_ascii=False, indent=2)
        
    with open("AddrFlowEasy.asm", "w") as f:
        f.write(DisasmFlow)
        
    with open("AddrFlowEasyWithJmp.asm", "w") as f:
        LsDisasmFlowKeys = list(DisasmFlowDirc.items())
        LsDisasmFlowKeys.sort(key=lambda x:x[0],reverse=False)
        for item in LsDisasmFlowKeys:
            f.write(item[1]+'\n')
     
    dbg.close()
    print("Finished!")