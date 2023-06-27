from LyScript32 import MyDebug
import sys
import time
import json

    
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    print '参数个数为:', len(sys.argv), '个参数。'
    print '参数列表:', str(sys.argv)
    
    if len(sys.argv)<2:
        print("请输入函数的地址范围")
        exit()
    
    FuncStartIP = int(sys.argv[1], 16)
    FuncEndIP = int(sys.argv[2], 16)
    if FuncStartIP > FuncEndIP:
        print("第一个参数是起始地址，第二个参数是终止地址")
        exit()
    
    dbg.set_breakpoint(FuncStartIP)
    dbg.set_debug("run")
   
    while True:
        eip = dbg.get_register("eip")
        # print(eip,FuncStartIP)
        # print("eip: 0x{:0>8X}".format(eip))
        # print("FuncStartIP: 0x{:0>8X}".format(FuncStartIP))
        if eip != FuncStartIP:
            dbg.set_debug("run")
            in_key = raw_input("press any key to continue...")
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