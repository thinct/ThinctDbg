import sys
import re
import time
import json
import gflags
from enum import Enum
from LyScript32 import MyDebug

# .\RuntimeTrace.py --S 0x00402029 --E 0x0040206A --StepIn 0x00402064 --StepIn 0x68B09B26 --MustAddr 0x68B09B0A --PauseOnce 0x68B09B0A
# .\RuntimeTrace.py --S 0x01071AD0 --E 0x01071BC1 --StartInModules 0x01060000 --EndInModules 0x01076FF2
# .\RuntimeTrace.py --S 0x004011A0 --E 0x004012ED --StartInModules 0x00400000 --EndInModules 0x00402FFF --noEnablePrtESP

# 定义标志
gflags.DEFINE_integer('S',                0x0, 'start point')
gflags.DEFINE_integer('E',                0x0, 'end point')
gflags.DEFINE_multi_int('Pause',          [], 'pause list')
gflags.DEFINE_multi_int('PauseOnce',      [], 'pause once list')
gflags.DEFINE_multi_int('StepIn',         [], 'Step into')
gflags.DEFINE_multi_int('MustAddr',       [], 'Must step to the Addr')
gflags.DEFINE_string('DisasmPart',        "", 'jmp')
gflags.DEFINE_multi_int('StartInModules', [], 'start in module')
gflags.DEFINE_multi_int('EndInModules',   [], 'end in module')
gflags.DEFINE_boolean('EnablePrtEBP',     True, 'enable print ebp')
gflags.DEFINE_boolean('EnablePrtESP',     True, 'enable print esp')

class StepStatus(Enum):
    StepOver = 0
    StepIn   = 1
    StepOut  = 2
    
if __name__ == "__main__":
    print('args count:', len(sys.argv))
    print('argv list:', str(sys.argv))
    if len(sys.argv)<2:
        print("please input disasm addr range")
        exit()
        
    # 解析命令行参数
    gflags.FLAGS(sys.argv)
    print(hex(gflags.FLAGS.S))
    FuncStartIP    = gflags.FLAGS.S
    FuncEndIP      = gflags.FLAGS.E
    PauseIPs       = gflags.FLAGS.Pause
    PauseIPOnce    = gflags.FLAGS.PauseOnce
    StepIns        = gflags.FLAGS.StepIn
    MustAddrs      = gflags.FLAGS.MustAddr
    DisasmPart     = gflags.FLAGS.DisasmPart
    StartInModules = gflags.FLAGS.StartInModules
    EndInModules   = gflags.FLAGS.EndInModules
    EnablePrtEBP   = gflags.FLAGS.EnablePrtEBP
    EnablePrtESP   = gflags.FLAGS.EnablePrtESP
    print('$$$', EnablePrtEBP, EnablePrtESP)
    if FuncStartIP >= FuncEndIP:
        print("the first is start addr and the second is end addr")
        exit()
        
    StepInModuleFlag = False
    HadStepInStatus  = StepStatus.StepOver
    if len(StartInModules) > 0 and len(EndInModules) > 0:
        StepInModuleFlag = True
        
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

    if len(StepIns)>0 and len(MustAddrs) == 0:
        MustAddrs = [FuncEndIP]
        
    regsJson       = {"AddrFlow":[]}
    DisasmFlow     = ""
    DisasmFlowDirc = {}
    EIPSet         = []
    EIPGoToSet     = []
    LastestIPFlag  = False
    EBPOld         = 0
    ESPOld         = 0
    while True:
        dbg.enable_commu_sync_time(False)
        eip = dbg.get_register("eip")
        if len(MustAddrs) > 0:
            if eip == MustAddrs[0]:
                MustAddrs.pop(0)
                if eip == FuncEndIP:
                    print("LastestIPFlag  IP  0x{:0>8X}".format(eip))
                    LastestIPFlag = True
        else:
            if eip == FuncEndIP:
                print("LastestIPFlag  IP  0x{:0>8X}".format(eip))
                LastestIPFlag = True
        
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
            
        
        if EBPOld != ebp and EnablePrtEBP:
            disasmFlowItem += "\n;"+"ebp : 0x{:0>8X}".format(ebp)
            EBPOld = ebp
        if ESPOld != esp and EnablePrtESP:
            print(EnablePrtESP)
            disasmFlowItem += "\n;"+"esp : 0x{:0>8X}".format(esp)
            ESPOld = esp
            
        #print(IPRegs)
        regsJson["AddrFlow"] += [IPRegs]
        DisasmFlowDirc[eip]  = disasmFlowItem
        DisasmFlow           += disasmFlowItem + "\n"
        print("currentRIP: 0x{:0>8X} eax: 0x{:0>8X}".format(eip, eax))
        
        dbg.enable_commu_sync_time(True)
        if StepInModuleFlag:
            InRangeFlag = False
            for i in range(len(StartInModules)):
                if eip >= StartInModules[i] and eip <= EndInModules[i]:
                    HadStepInStatus = StepStatus.StepIn
                    InRangeFlag   = True
                    break
            if InRangeFlag is False:
                HadStepInStatus = StepStatus.StepOut
        else:
            if eip in StepIns:
                HadStepInStatus = StepStatus.StepIn
                
        if HadStepInStatus == StepStatus.StepOver:
            dbg.set_debug("StepOver")
        else:
            if HadStepInStatus == StepStatus.StepOut:
                print("Step Out...")
                dbg.set_debug("StepOut")
            else:
                print("Step Into...")
                dbg.set_debug("StepIn")
        
        if LastestIPFlag is True:
            break
   
        
    #print(regsJson)
    with open("AddrFlow.json", "w") as f:
        json.dump(regsJson["AddrFlow"], f, ensure_ascii=False, indent=2)
        
    with open("AddrFlowEasy.asm", "w") as f:
        f.write(DisasmFlow)
        
    LsDisasmFlowKeys = list(DisasmFlowDirc.items())
    LsDisasmFlowKeys.sort(key=lambda x:x[0],reverse=False)
    AddrJmpList    = []
    disasmLineList = []
    for item in LsDisasmFlowKeys:
        disasmLine = item[1]
        if disasmLine[0] == ';':
            disasmLine = disasmLine[1:]
            pattern    = r"\bj[a-z]+\b\s+(0x\w+)"
            match      = re.search(pattern, disasmLine)
            if match:
                jmpAddr     = match.group(1)
                AddrJmpList += [jmpAddr]
                disasmLine  = disasmLine[:14]+disasmLine[14:].replace(jmpAddr, "LABEL_"+jmpAddr)
        disasmLineList += [disasmLine]
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