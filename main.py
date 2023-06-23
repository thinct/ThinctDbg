from LyScript32 import MyDebug
import sys
import time

    
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
        try:
            eip = dbg.get_register("eip")
            print(eip,FuncStartIP)
            print("eip: {:#X}".format(eip))
            print("FuncStartIP: {:#X}".format(FuncStartIP))
            if eip != FuncStartIP:
                dbg.set_debug("run")
                input("press any key to continue...")
                continue
            dbg.delete_breakpoint(FuncStartIP)
            break
        except:
            continue

    while True:
        eip = dbg.get_register("eip")
        if eip >= FuncEndIP:
            break
        print("currentRIP: {:#X}".format(eip))
        dbg.set_debug("StepOver")
    
    dbg.close()
    print("Finished!")