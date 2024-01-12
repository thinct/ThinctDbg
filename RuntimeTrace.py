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

# 0x.*add.*,.*0x[0-9A-F]
# (value_0x.*")  $1 color=red

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
gflags.DEFINE_boolean('EnableSnapMode',       False, 'just focus on snippet of code')
gflags.DEFINE_boolean('EnableFastMode',       False, 'just focus on range S and E, inner -> stepover, outter -> run')

class StepStatus(Enum):
    StepOver = 0
    StepIn   = 1
    StepOut  = 2
    Run      = 3

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
    with open('ExternMsg.txt', 'r') as file:
        ExMsg = file.readline().strip().upper()
        if ExMsg == "stdout".upper():
            sys.stdout = open('stdout.log', mode = 'w',encoding='utf-8')

    print('args count:', len(sys.argv))
    print('argv list:', str(sys.argv))
    if len(sys.argv)<2:
        print("please input disasm addr range")
        exit()

    SnapModeActiving = False

    # Parse command line arguments
    gflags.FLAGS(sys.argv)
    while True:
        FuncStartIP          = gflags.FLAGS.S
        FuncEndIP            = gflags.FLAGS.E
        PauseIPs             = gflags.FLAGS.Pause
        PauseIPOnce          = gflags.FLAGS.PauseOnce
        StepIns              = gflags.FLAGS.StepIn
        MustAddrs            = gflags.FLAGS.MustAddr
        DisasmPart           = gflags.FLAGS.DisasmPart
        StartInModules       = gflags.FLAGS.StartInModules
        EndInModules         = gflags.FLAGS.EndInModules
        EnablePrtEBP         = gflags.FLAGS.EnablePrtEBP
        EnablePrtESP         = gflags.FLAGS.EnablePrtESP
        EnableModifyCallAddr = gflags.FLAGS.EnableModifyCallAddr
        EnableSnapMode       = gflags.FLAGS.EnableSnapMode
        EnableFastMode       = gflags.FLAGS.EnableFastMode

        dbg          = MyDebug()
        connect_flag = dbg.connect()
        print("MyDebug connect status: {}".format(connect_flag))

        eip = dbg.get_register("eip")

        if not EnableSnapMode and not EnableFastMode:
            while eip != FuncStartIP:
                print("0x{:0>8X} : 0x{:0>8X}".format(eip, FuncStartIP))
                in_key = input("The starting point has not been reached, so click any key to continue...")
                in_key = in_key.strip().upper()
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
        StepInStack       = []
        HadStepInStatus   = StepStatus.StepOver

        if len(StepIns)>0 and len(MustAddrs) == 0:
            MustAddrs = [FuncEndIP]

        while True:
            with open('ExternMsg.txt', 'r') as file:
                ExMsg = file.readline().strip().upper()
                if ExMsg.strip() != "":
                    print("ExMsg:",ExMsg)
                    with open('ExternMsg.txt', 'w') as file:
                        pass
                    if ExMsg == "q".upper() or ExMsg == "quit".upper():
                        print("Extern MSG==>quit!")
                        dbg.close()
                        exit()
                    elif ExMsg == "restart".upper():
                        RestartScriptFlag = True
                        break
                    elif ExMsg == "over".upper():
                        LastestIPFlag = True
                        break
                    elif ExMsg == "SnapStart".upper():
                        RestartScriptFlag = True # it as same as restart
                        SnapModeActiving  = True
                        break
                    elif ExMsg == "SnapEnd".upper(): 
                        LastestIPFlag    = True # it as same as over
                        SnapModeActiving = False
                        break

            if EnableSnapMode and not LastestIPFlag and SnapModeActiving:
                dbg.enable_commu_sync_time(True)
                print('.',end='',flush=True)
                dbg.set_debug("run")
                continue

            dbg.enable_commu_sync_time(False)
            eip = dbg.get_register("eip")
            print("-->  IP  0x{:0>8X}".format(eip))
            
            if EnableFastMode is True:
                if eip >= FuncStartIP and eip <= FuncEndIP:
                    HadStepInStatus = StepStatus.StepOver
                else:
                    HadStepInStatus = StepStatus.Run

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
            elif eip == FuncEndIP:
                PauseConditionTriggeredFlag = True
                print("Condition Triggered : Arrived FuncEndIP...")
            if PauseConditionTriggeredFlag: 
                in_key = input("Press normal key to continue...\n").strip().upper()
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
            if eip in PauseIPOnce:
                PauseIPOnce.remove(eip)
                print(PauseIPOnce)
                in_key = input("This is a pause point where you can make changes to the x64dbg...")

            if eip in EIPSet:
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

            disasmLine = ""
            if MemRefValueGroup is not None:
                refValueExp = MemRefValueGroup[0]
                refAndValue = get_ref_and_value(dbg, refValueExp)
                if (refAndValue is not None):
                    if MemRefValueGroup[1] == refAndValue[0] and MemRefValueGroup[2] != refAndValue[1]:
                        print(";0;{}=[0x{:0>8X}]=0x{:0>8X}\n".format(refValueExp,refAndValue[0],refAndValue[1]))
                        disasmLine =  ";{}=[0x{:0>8X}]=0x{:0>8X}  <-- Modify\n".format(refValueExp,refAndValue[0],refAndValue[1]) 
                        MemRefKV   += [("0x{:0>8X}".format(refAndValue[0]),"0x{:0>8X}".format(refAndValue[1]))]
                MemRefValueGroup = None

            disasmLine += "/*0x{:0>8X}*/    {}".format(eip, disasm)
            print(disasmLine)
            if disasm[0] == 'j': # jmp
                disasmLine = ";" + disasmLine
                if len(disasm) == 14:
                    if int(str(disasm[4:14]), 16) < eip:
                        disasmLine += ";GOTO BACK"
                if len(disasm) == 13:
                    if int(str(disasm[3:13]), 16) < eip:
                        disasmLine += ";GOTO BACK"
            elif EnableModifyCallAddr and disasm[0:4] == 'call' and disasm[5:7] == '0x':
                disasmLine = 'mov eax, ' + disasm[5:15] + '\n' + "/*0x{:0>8X}*/    call eax".format(eip)
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
                        disasmLine       =  disasmLine + "\n;{}=[0x{:0>8X}]=0x{:0>8X}".format(refValueExp,refAndValue[0],refAndValue[1]) 
                        MemRefValueGroup =  (refValueExp,refAndValue[0],refAndValue[1])
                        MemRefKV         += [("0x{:0>8X}".format(refAndValue[0]),"0x{:0>8X}".format(refAndValue[1]))]

            if EBPOld != ebp and EnablePrtEBP:
                EBPOld     = ebp
                disasmLine = ";ebp : 0x{:0>8X}\n".format(ebp) + disasmLine
            if ESPOld != esp and EnablePrtESP:
                ESPOld     = esp
                disasmLine = ";esp : 0x{:0>8X}\n".format(esp) + disasmLine

            #print(IPRegs)
            DisasmFlowDirc[eip]  =  disasmLine
            regsJson["AddrFlow"] += [IPRegs]
            DisasmFlow           += disasmLine + "\n"
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

            eipInRangeOfModulesFlag = False
            for i in range(len(StartInModules)):
                if eip >= StartInModules[i] and eip <= EndInModules[i]:
                    eipInRangeOfModulesFlag = True
                    break
            if eipInRangeOfModulesFlag is False and len(StepInStack)>0:
                HadStepInStatus = StepStatus.StepOut

            if disasm[0:4] == 'call':
                if eip in StepIns or eipInRangeOfModulesFlag:
                    HadStepInStatus = StepStatus.StepIn
                    asm_len = dbg.assemble_code_size(disasm)
                    StepInStack += [eip + asm_len]
                    print("stack push(next eip): 0x{:0>8X}".format(StepInStack[-1]))                        

            if HadStepInStatus == StepStatus.StepOver:
                print("HadStepInStatus : Step Over.")
                dbg.set_debug("StepOver")
            else:
                if HadStepInStatus == StepStatus.StepOut:
                    print("HadStepInStatus : Step Out.")
                    dbg.set_debug("StepOut")
                elif HadStepInStatus == StepStatus.Run:
                    print("HadStepInStatus : Run.")
                    dbg.set_debug("run")
                else:
                    print("HadStepInStatus : Step Into.")
                    dbg.set_debug("StepIn")

        dbg.close()
        if RestartScriptFlag:
            
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

        print("Finished!")
        exit()