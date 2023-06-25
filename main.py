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
        # print("eip: {:#X}".format(eip))
        # print("FuncStartIP: {:#X}".format(FuncStartIP))
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
    while True:
        eip = dbg.get_register("eip")
        if eip > FuncEndIP:
            break
        eax = dbg.get_register("eax")
        ecx = dbg.get_register("ecx")
        edx = dbg.get_register("edx")
        ebx = dbg.get_register("ebx")
        ebp = dbg.get_register("ebp")
        esp = dbg.get_register("esp")
        esi = dbg.get_register("esi")
        edi = dbg.get_register("edi")
        disasm = dbg.get_disasm_one_code(eip)
        IPRegs = {"IP":"{:#X}".format(eip), "Disasm":"{}".format(disasm),"Regs":{"eax":"{:#X}".format(eax)\
        ,"ecx":"{:#X}".format(ecx),"edx":"{:#X}".format(edx),"ebx":"{:#X}".format(ebx),"ebp":"{:#X}".format(ebp)\
        ,"esp":"{:#X}".format(esp),"esi":"{:#X}".format(esi),"edi":"{:#X}".format(edi)}}
            
        disasmFlowItem = "/*{:#X}*/    {}".format(eip, disasm)
        if disasm[0] == 'j':
            disasmFlowItem = ";" + disasmFlowItem
        elif disasm[0:4] == 'call' and disasm[5:7] == '0x':
            disasmFlowItem = 'mov eax, ' + disasm[5:15] + '\n' + "/*{:#X}*/    call eax".format(eip)
        #print(IPRegs)
        regsJson["AddrFlow"] += [IPRegs]
        DisasmFlow += disasmFlowItem + "\n"
        print("currentRIP: {:#X} eax: {:#X}".format(eip, eax))
        
        dbg.enable_commu_sync_time(True)
        dbg.set_debug("StepOver")
        dbg.enable_commu_sync_time(False)
   
        
    #print(regsJson)
    with open("AddrFlow.json", "w") as f:
        json.dump(regsJson["AddrFlow"], f, ensure_ascii=False, indent=2)
        
    with open("AddrFlowEasy.asm", "w") as f:
        f.write(DisasmFlow)
     
    dbg.close()
    print("Finished!")