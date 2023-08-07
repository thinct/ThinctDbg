from LyScript32 import MyDebug

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
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    eip = dbg.get_register("eip")
    base = dbg.get_module_base("mfcapplication1.exe")
    print("base: {:#X}".format(base))
    entry = dbg.get_local_module_entry()
    print("模块入口: {:#X}".format(dbg.get_local_module_entry()))
    
    bpOld = None
    currentRIP = base + 0x1000
    currentRIP = 0x01202FAB
    while True:
        if currentRIP+1 > entry:
            break
        ref = GetHexCode(dbg,currentRIP)
        if len(ref) == 1 and ref[0] == 0xcc:
        
            # 指令長度在一定控制在一定範圍内
            if bpOld is not None:
                # print("will breakpoint: len:{:#X} IP:{:#X}".format(currentRIP-bpOld, bpOld))
                if (currentRIP-bpOld<10 or currentRIP-bpOld>80):
                    print("delete breakpoint: len:{:#X} IP:{:#X}".format(currentRIP-bpOld, bpOld))
                    dbg.delete_breakpoint(bpOld)
                bpOld = None
        
            refNormal = GetHexCode(dbg,currentRIP+1)
            #if len(ref)>0 and  ref[0] != 0xcc and ref[0] == 0x6A:
            if len(refNormal)>0 and  refNormal[0] != 0xcc:
                print("currentRIP: {:#X}".format(currentRIP+1))
                dbg.set_breakpoint(currentRIP+1)
                bpOld = currentRIP+1
                currentRIP = currentRIP + len(refNormal)
                continue
        if len(ref) == 0:
            #print("----currentRIP: {:#X}".format(currentRIP))
            currentRIP = currentRIP + 1
            continue
        currentRIP = currentRIP + len(ref)
        
    
    dbg.close()
    print("Finished!")