from LyScript32 import MyDebug
import time

    
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    # eip = dbg.get_register("eip")
    # print("currentRIP: {:#X}".format(eip))
    # dbg.set_debug("StepOver")   
    # 首先定义一个脚本变量
    ref = dbg.run_command_exec("eax=123")

    # 将脚本返回值放到eax寄存器，或者开辟一个堆放到堆里
    #dbg.run_command_exec("eax=$addr")

    # 最后拿到寄存器的值
    print(hex(dbg.get_register("eax")))
    
    dbg.set_debug("StepOver")
    
    dbg.close()
    print("Finished!")