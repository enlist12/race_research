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
parser.add_argument("-t","--time",dest="time",type=int,required=False,help="time",default=60)
parser.add_argument("-c","--batch",dest="batch",type=int,required=False,help="batch",default=5)


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
	        -smp 4 \
	        -kernel {args.bzImage} \
	        -append "console=ttyS0 root=/dev/sda kasan_multi_shot=1 earlyprintk=serial net.ifnames=0" \
	        -net nic,model=e1000 \
	        -drive file={args.image},format=raw \
            -snapshot \
	        -enable-kvm \
	        -nographic  '

KASAN_string="KASAN: use-after-free"

Slab_string="KASAN: slab-use-after-free"

warning_split="=========================================="

STOP="Rebooting in"

single_report=[]

sum_report=[]

success_num=0

rank=0

def get_kasan_report(num:int):
    report=[]
    global lock
    global rank
    global single_report
    port=unused_tcp_port()
    cmdline=f'-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:{port}-:22 '
    qemu=qemu_cmd+cmdline
    vm=process(qemu,shell=True)
    try:
        vm.recvuntil(b"syzkaller login:",timeout=300)
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        log.error(f"Something wrong as VM-{num} start")
        vm.close()
        return
    vm.sendline(b"root")
    log.info(f"VM-{num} start successfully !!!")
    try:
        os.system(f'scp -P {port} -o "StrictHostKeyChecking no" -i {args.rsa}  {args.poc}  root@localhost:/root')
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        log.error(f"Something wrong as VM-{num} ssh connection")
        vm.close()
        return
    log.info("POC upload")
    vm.clean()
    poc=os.path.basename(args.poc)
    cmd=f"./{poc}"
    vm.sendline(cmd.encode())
    find_kasan=0
    total_time=args.time
    start=time.time()
    kasans=dict()
    datas=[]
    last_time=0
    last_num=0
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
        report.append(line)
        if STOP in line:
            log.info(f"VM-{num} Rebooting")
            break 
        if not find_kasan and (KASAN_string in line or Slab_string in line):
            for k in range(len(report) - 1, -1, -1):
                if warning_split in report[k]:
                    report=report[k:]
                    break
            kasans[line]=True
            datas.append(line)
            log.info(f"VM-{num} Find KASAN Report")
            last_time=time.time()
            find_kasan=1
        if find_kasan and (KASAN_string in line or Slab_string in line):
            if line in kasans:
                pass
            else:
                kasans[line]=True
                datas.append(line)
        if not find_kasan and time.time()-start>total_time:
            log.error(f"VM-{num} NO KASAN Report Triggered")
            break
        if find_kasan and time.time()-last_time>=180:
            last_time=time.time()
            nu=len(datas)-last_num
            log.info(f"VM-{num}  : In last 3 mins , kasan inc {nu}")
            last_num=len(datas)
            if nu==0:
                break
    with lock:  
        single_report.append(datas)
        if not datas:
            return
        with open(f"VM-{rank}","w") as f:
            for line in report:
                f.write(line+"\n")
        rank+=1 
        return
            

thread=[]

rr=True

is_update=0

batch=0

while 1:
    for j in range(args.num):
        thread.append(threading.Thread(target=get_kasan_report,args=(j,)))
        thread[j].start()
    for j in range(args.num):
        thread[j].join()
    if rr:
        if all(x == single_report[0] for x in single_report):
            print("\033[31mThis is pure UAF\033[0m")
            break
        else:
            print("\033[31mThis is concurrency UAF\033[0m")
        rr=False
    for j in single_report:
        for i in j:
            if i not in sum_report:
                sum_report.append(i)
                is_update+=1
    log.info(f"\033[31mUpdate {is_update} KASAN Report\033[0m")  
    if not is_update:
        batch+=1
        if batch>=args.batch:
            log.info("Collection Stop")
            break
    else:
        batch=0
    single_report.clear()
    is_update=0
    thread.clear()

if rr:
    pass

num=len(sum_report)

log.info(f"Collect KASAN Report {num} kinds")

with open("title.txt","w") as f:
    for line in sum_report:
        f.write(line+"\n")






