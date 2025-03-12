from pwn import *
import argparse
import os
import threading
import logging
import time
import random
import socket

lock = threading.Lock()

def random_port():
    return random.randint(1024, 65535)

def unused_tcp_port():
    while True:
        port = random_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("localhost", port))
                return port
            except OSError:
                continue



logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("UAF Judge")

parser=argparse.ArgumentParser()

parser.add_argument("-b","--bzImage",dest="bzImage",type=str,required=True,help="bzImage")
parser.add_argument("-i","--image",dest="image",type=str,required=True,help="Syzkaller Image")
parser.add_argument("-p","--poc",dest="poc",type=str,required=True,help="POC")
parser.add_argument("-r","--rsa",type=str,dest="rsa",required=True,help="id_rsa")
parser.add_argument("-n","--num",type=int,dest="num",required=False,help="num",default=10)
parser.add_argument("-o","--output",action="store_true",dest="output",required=False,help="output")
parser.add_argument("-t","--time",dest="time",type=int,required=False,help="time",default=60)


args=parser.parse_args()

if (
    os.path.isfile(args.image) 
    and os.path.isfile(args.bzImage)
    and os.path.isfile(args.poc)
    and os.path.isfile(args.rsa)
):
    pass
else:
    print("[-] File does not exist")
    exit(1)

if args.num<1:
    print("[-] Unreasonable num")
    exit(0)

qemu_cmd=f'qemu-system-x86_64 \
	        -m 2G \
	        -smp 2 \
	        -kernel {args.bzImage} \
	        -append "console=ttyS0 root=/dev/sda kasan_multi_shot=1 earlyprintk=serial net.ifnames=0" \
	        -net nic,model=e1000 \
	        -drive file={args.image},format=raw \
            -snapshot \
	        -enable-kvm \
	        -nographic  '

KASAN_string="KASAN: use-after-free"

Slab_string="KASAN: slab-use-after-free"

attempt=3

report=[]

success_num=0

def get_kasan_report(num:int,atp:int):
    global lock
    port=unused_tcp_port()
    cmdline=f'-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:{port}-:22 '
    qemu=qemu_cmd+cmdline
    vm=process(qemu,shell=True)
    try:
        vm.recvuntil(b"syzkaller login:",timeout=300)
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        log.error(f"Something wrong as VM-{num} start , try {attempt-atp}")
        if atp>0:
            vm.close()
            get_kasan_report(num,atp-1)
            return
        else:
            return
    vm.sendline(b"root")
    log.info(f"VM-{num} start successfully !!!")
    try:
        os.system(f'scp -P {port} -o "StrictHostKeyChecking no"   -i {args.rsa}  {args.poc}  root@localhost:/root')
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        log.error(f"Something wrong as VM-{num} ssh connection , try {attempt-atp}")
        if atp>0:
            vm.close()
            get_kasan_report(num,atp-1)
            return
        else:
            return
    log.info("POC upload")
    vm.clean()
    poc=os.path.basename(args.poc)
    cmd=f"./{poc}"
    vm.sendline(cmd.encode())
    data=[]
    find_kasan=0
    total_time=args.time
    start=time.time()
    while True:
        try:
            line=vm.recvline(timeout=10)
        except Exception as e:
            log.info("Nothing to Recive!!!")
            break
        #print(line.decode().strip())
        line=line.decode().strip()
        if "] " in line:
            index=line.find("] ")
            line=line[index+2:]
        data.append(line)
        if not find_kasan and (KASAN_string in line or Slab_string in line):
            log.info(f"VM-{num} Find KASAN Report")
            data=data[-2:]
            start_time=time.time()
            find_kasan=1
        if find_kasan and time.time()-start_time>30:
            log.info(f"VM-{num} Reciving KASAN Report Ending")
            break
        if not find_kasan and time.time()-start>total_time:
            log.error(f"VM-{num} NO KASAN Report Triggered")
            break
    if args.output:
        with open(f"VM-{num}","w") as f:
            for line in data:
                f.write(line+"\n")
    datas=[]
    kasan=dict()
    if find_kasan:
        for line in data:
            if KASAN_string not in line and Slab_string not in line:
                continue
            if line in kasan:
                continue
            datas.append(line)
            kasan[line]=True
    else:
        if atp>0:
            log.info(f"VM-{num} Try Again")
            vm.close()
            get_kasan_report(num,atp-1)
            return
        else:
            return
    with lock:
        globals()["report"].append(datas)
        globals()["success_num"]+=1
    log.info(f"VM-{num} Close")
    vm.close()
    return                             

thread=[]

for j in range(args.num):
    thread.append(threading.Thread(target=get_kasan_report,args=(j,attempt)))
    thread[j].start()

for j in range(args.num):
    thread[j].join()
    
log.info(f"ALL VM End,Success:{success_num}/{args.num}")

if success_num<2:
    log.error("Success_num is too low")
    exit(1)

if all(x == report[0] for x in report):
    print("This is pure UAF")
else:
    print("This is concurrency UAF")



