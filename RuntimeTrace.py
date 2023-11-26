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
# .\RuntimeTrace.py --S 0x004011A0 --E 0x004012ED --StartInModules 0x00400000 --EndInModules 0x00402FFF --noEnablePrtESP --ModifyCallAddr

# convert to value  : addr_0x0{3,7}([1-9A-F]*\w*) --> value_0x$1
# convert to stack  : addr_(0x0019F\w+) --> stack_$1
# clear label index : \[label="\w+?"\]

# Definition flags
# About instruction
gflags.DEFINE_integer('S',                    0x0,   'start point')
gflags.DEFINE_integer('E',                    0x0,   'end point')
gflags.DEFINE_multi_int('Pause',              [],    'pause list')
gflags.DEFINE_multi_int('PauseOnce',          [],    'pause once list')
gflags.DEFINE_multi_int('StepIn',             [],    'Step into')
gflags.DEFINE_multi_int('MustAddr',           [],    'Must step to the Addr')
gflags.DEFINE_string('DisasmPart',            "",    'jmp')
gflags.DEFINE_multi_int('StartInModules',     [],    'start in module')
gflags.DEFINE_multi_int('EndInModules',       [],    'end in module')
gflags.DEFINE_boolean('EnablePrtEBP',         True,  'enable print ebp')
gflags.DEFINE_boolean('EnablePrtESP',         True,  'enable print esp')
gflags.DEFINE_boolean('EnableModifyCallAddr', False, 'enable modify the absolute call address')

class StepStatus(Enum):
    StepOver = 0
    StepIn   = 1
    StepOut  = 2 
    
# strStrExp like as [ebp-4]
# Consider only memory reads and writes in square brackets (both direct and indirect addressing)
def get_ref_and_value(dbg, strStrExp):
    time.sleep(0.1)
    strStrExpWithRef = strStrExp[1:-1] # --> ebp-4
    ref1 = dbg.run_command_exec("$reg=eax")
    ref1 = dbg.run_command_exec("$addr="+strStrExpWithRef)
    ref1 = dbg.run_command_exec("eax=$addr")
    
    time.sleep(0.1)
    refAddr = dbg.get_register("eax")
    ref1    = dbg.run_command_exec("eax=$reg")
    
    time.sleep(0.1)
    refAddr = 0x100000000 + refAddr if refAddr < 0 else refAddr # just for 32bit
    if refAddr < 0x2000: # Not allow access
        return None
    ref2 = dbg.run_command_exec("mov eax, "+strStrExp)
    
    time.sleep(0.1)
    refValue = dbg.get_register("eax")
    ref1     = dbg.run_command_exec("eax=$reg")
    
    time.sleep(0.1)
    refValue = 0x100000000+refValue if refValue < 0 else refValue
    return refAddr,refValue if (ref1 and ref2) else None
    
    
if __name__ == "__main__":
    print('args count:', len(sys.argv))
    print('argv list:', str(sys.argv))
    if len(sys.argv)<2:
        print("please input disasm addr range")
        exit()
        
    # Parse command line arguments
    gflags.FLAGS(sys.argv)
                
    while True:
        FuncStartIP            = gflags.FLAGS.S
        FuncEndIP              = gflags.FLAGS.E
        PauseIPs               = gflags.FLAGS.Pause
        PauseIPOnce            = gflags.FLAGS.PauseOnce
        StepIns                = gflags.FLAGS.StepIn
        MustAddrs              = gflags.FLAGS.MustAddr
        DisasmPart             = gflags.FLAGS.DisasmPart
        StartInModules         = gflags.FLAGS.StartInModules
        EndInModules           = gflags.FLAGS.EndInModules
        EnablePrtEBP           = gflags.FLAGS.EnablePrtEBP
        EnablePrtESP           = gflags.FLAGS.EnablePrtESP
        EnableModifyCallAddr   = gflags.FLAGS.EnableModifyCallAddr
        if FuncStartIP >= FuncEndIP:
            print("the first is start addr and the second is end addr")
            exit()
            
        dbg          = MyDebug()
        connect_flag = dbg.connect()
        print("MyDebug connect status: {}".format(connect_flag))
            
        eip = dbg.get_register("eip")
        while eip != FuncStartIP:
            print("0x{:0>8X} : 0x{:0>8X}".format(eip, FuncStartIP))
            in_key = input("The starting point has not been reached, so click any key to continue...")
            in_key = in_key.upper()
            if in_key == "q".upper() or in_key == "quit".upper():
                print("quit!")
                dbg.close()
                exit()
            dbg.set_breakpoint(FuncStartIP)
            dbg.set_debug("run") 
            eip = dbg.get_register("eip")
            dbg.delete_breakpoint(FuncStartIP)

            
        regsJson          = {"AddrFlow":[]}
        DisasmFlow        = ""
        DisasmFlowDirc    = {}
        EIPSet            = []
        EIPGoToSet        = []
        LastestIPFlag     = False
        EBPOld            = 0
        ESPOld            = 0
        MemRefValueGroup  = None
        MemRefKV          = []
        StartTime         = time.time()
        EipOld            = eip
        RestartScriptFlag = False
        StepInCounter     = 0
        StepInStack       = []
        HadStepInStatus   = StepStatus.StepOver
        
        if len(StepIns)>0 and len(MustAddrs) == 0:
            MustAddrs = [FuncEndIP]
            
        while True:
            with open('ExternMsg.txt', 'r') as file:
                ExMsg = file.readline().strip().upper()
                if len(ExMsg)>0:
                    with open('ExternMsg.txt', 'w') as file:
                        pass  
                    print("ExMsg:",ExMsg)
                    if ExMsg == "Broken".upper():
                        in_key = input("Extern MSG:Press normal key to continue...\n").upper()
                        if in_key == "q".upper() or in_key == "quit".upper():
                            print("Extern MSG==>quit!")
                            dbg.close()
                            exit()
                        elif in_key == "restart".upper():
                            RestartScriptFlag = True
                            break
                        elif in_key == "over".upper():
                            LastestIPFlag = True
                            break              
            
            dbg.enable_commu_sync_time(False)
            eip = dbg.get_register("eip")
            print("-->  IP  0x{:0>8X}".format(eip))
            
            if len(StepInStack)>0 and StepInStack[-1] == eip:
                HadStepInStatus = StepStatus.StepOver
                print("stack pop: 0x{:0>8X}".format(StepInStack.pop()))
            
            if EipOld != eip:
                # Current eip at function ret then step over
                StartTime = time.time()
                EipOld    = eip
                
            PauseConditionTriggeredFlag = False
            if time.time()-StartTime > 3:
                PauseConditionTriggeredFlag = True
                print("Condition Triggered : Timeout...")
            if eip == FuncStartIP:
                PauseConditionTriggeredFlag = True
                print("Condition Triggered : Arrived FuncStartIP...")
            if eip == FuncEndIP:
                PauseConditionTriggeredFlag = True
                print("Condition Triggered : Arrived FuncEndIP...")
            if PauseConditionTriggeredFlag: 
                in_key = input("Press normal key to continue...\n").upper()
                if in_key == "q".upper() or in_key == "quit".upper():
                    print("==>quit!")
                    StartTime = time.time()
                    dbg.close()
                    exit()
                elif in_key == "c".upper() or in_key == "continue".upper():
                    print("==>continue!")
                    continue
                elif in_key == "restart".upper():
                    RestartScriptFlag = True
                    break
            
            if eip <0x1000:
                input("pause for invalid eip: 0x{:0>8X}".format(eip))
                continue
            
            if len(MustAddrs) > 0:
                if eip == MustAddrs[0]:
                    MustAddrs.pop(0)
                    input("pause for MustAddrs eip: 0x{:0>8X}".format(eip))
                    if eip == FuncEndIP:
                        print("LastestIPFlag  IP  0x{:0>8X} via MustAddrs".format(eip))
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
                
            if LastestIPFlag is False and eip in EIPSet:
                dbg.enable_commu_sync_time(True)
                print("Step Over Continue when eip existed...")
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
            IPRegs = { "IP":"0x{:0>8X}".format(eip)          \
                     , "Disasm":"{}".format(disasm)          \
                     , "Regs":{"eax":"0x{:0>8X}".format(eax) \
                     , "ecx":"0x{:0>8X}".format(ecx)         \
                     , "edx":"0x{:0>8X}".format(edx)         \
                     , "ebx":"0x{:0>8X}".format(ebx)         \
                     , "ebp":"0x{:0>8X}".format(ebp)         \
                     , "esp":"0x{:0>8X}".format(esp)         \
                     , "esi":"0x{:0>8X}".format(esi)         \
                     , "edi":"0x{:0>8X}".format(edi)}        \
                     }
            
            disasmFlowItem = ""
            if MemRefValueGroup is not None:
                refValueExp = MemRefValueGroup[0]
                refAndValue = get_ref_and_value(dbg, refValueExp)
                if (refAndValue is not None):
                    if MemRefValueGroup[1] == refAndValue[0] and MemRefValueGroup[2] != refAndValue[1]:
                        print(";0;{}=[0x{:0>8X}]=0x{:0>8X}\n".format(refValueExp,refAndValue[0],refAndValue[1]))
                        disasmFlowItem =  ";{}=[0x{:0>8X}]=0x{:0>8X}  <-- Modify\n".format(refValueExp,refAndValue[0],refAndValue[1]) 
                        MemRefKV       += [("0x{:0>8X}".format(refAndValue[0]),"0x{:0>8X}".format(refAndValue[1]))]
                MemRefValueGroup = None
                
            disasmFlowItem += "/*0x{:0>8X}*/    {}".format(eip, disasm)
            print(disasmFlowItem)
            if disasm[0] == 'j': # jmp
                disasmFlowItem = ";" + disasmFlowItem
                if len(disasm) == 14:
                    if int(str(disasm[4:14]), 16) < eip:
                        disasmFlowItem += ";GOTO BACK"
                if len(disasm) == 13:
                    if int(str(disasm[3:13]), 16) < eip:
                        disasmFlowItem += ";GOTO BACK"
            elif EnableModifyCallAddr and disasm[0:4] == 'call' and disasm[5:7] == '0x':
                disasmFlowItem = 'mov eax, ' + disasm[5:15] + '\n' + "/*0x{:0>8X}*/    call eax".format(eip)
            else:
                '''
                disasm="lea eax,dword ptr ss:[ebp-4]"
                disasm="mov dword ptr ds:[edi],esi"
                '''
                matchRefAddr = re.compile(r'\[([^\]]+)\]').search(disasm)
                if matchRefAddr:
                    refValueExp = "[{}]".format(matchRefAddr.group(1))
                    refAndValue = get_ref_and_value(dbg, refValueExp)
                    if (refAndValue is not None):
                        #[edi]=[0x5c53c0]=0x888
                        print(";1;{}=[0x{:0>8X}]=0x{:0>8X}".format(refValueExp,refAndValue[0],refAndValue[1]))
                        disasmFlowItem   =  disasmFlowItem + "\n;{}=[0x{:0>8X}]=0x{:0>8X}".format(refValueExp,refAndValue[0],refAndValue[1]) 
                        MemRefValueGroup =  (refValueExp,refAndValue[0],refAndValue[1])
                        MemRefKV         += [("0x{:0>8X}".format(refAndValue[0]),"0x{:0>8X}".format(refAndValue[1]))]
                    
            if EBPOld != ebp and EnablePrtEBP:
                EBPOld         = ebp
                disasmFlowItem = ";ebp : 0x{:0>8X}\n".format(ebp) + disasmFlowItem
            if ESPOld != esp and EnablePrtESP:
                ESPOld         = esp
                disasmFlowItem = ";esp : 0x{:0>8X}\n".format(esp) + disasmFlowItem
                
            #print(IPRegs)
            DisasmFlowDirc[eip]  =  disasmFlowItem
            regsJson["AddrFlow"] += [IPRegs]
            DisasmFlow           += disasmFlowItem + "\n"
            print("currentRIP: 0x{:0>8X} eax: 0x{:0>8X}".format(eip, eax))
            
            dbg.enable_commu_sync_time(True)
            if LastestIPFlag is True:
                print("Step Over when lastest...")
                dbg.set_debug("StepOver")
                break
            
            # Current eip at function ret then step over
            if HadStepInStatus == StepStatus.StepOut:
                print("Step Over from ret...")
                HadStepInStatus = StepStatus.StepOver
                dbg.set_debug("StepOver")
                continue
                
            HadStepInStatus = StepStatus.StepOver
            if len(StepInStack)>0:
                HadStepInStatus = StepStatus.StepOut
                
            if disasm[0:4] == 'call':
                if eip in StepIns:
                    HadStepInStatus = StepStatus.StepIn
                    asm_len = dbg.assemble_code_size(disasm)
                    StepInStack += [eip + asm_len]
                    print("stack push(next eip): 0x{:0>8X}".format(StepInStack[-1]))
                else:
                    for i in range(len(StartInModules)):
                        if eip >= StartInModules[i] and eip <= EndInModules[i]:
                            HadStepInStatus = StepStatus.StepIn
                            asm_len = dbg.assemble_code_size(disasm)
                            StepInStack += [eip + asm_len]
                            print("stack push(next eip): 0x{:0>8X}".format(StepInStack[-1]))
                            break
                    
            if HadStepInStatus == StepStatus.StepOver:
                print("HadStepInStatus : Step Over.")
                dbg.set_debug("StepOver")
            else:
                if HadStepInStatus == StepStatus.StepOut:
                    print("HadStepInStatus : Step Out.")
                    dbg.set_debug("StepOut")
                else:
                    print("HadStepInStatus : Step Into.")
                    dbg.set_debug("StepIn")
       
        if RestartScriptFlag:
            dbg.close()
            continue
            
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
        
        with open("MemoryChart.gv", "w") as f:
            index_order = 0
            strMemoryLink = ""
            for item in MemRefKV:
                strMemoryLink += '''    addr_{} -> addr_{} [label="{}"]\n'''.format(item[0], item[1], index_order)
                index_order += 1
            strGVChart = "strict digraph Memory {\n    node [shape=box];\n    rankdir = LR;\n\n" + strMemoryLink + r"}"
            f.write(strGVChart)
            
        dbg.close()
        print("Finished!")
        exit()