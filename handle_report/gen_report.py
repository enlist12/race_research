import argparse
import os

parser=argparse.ArgumentParser()

parser.add_argument("--reports","-r",dest="reports",type=str,default="report0",help="The name of the report file")
parser.add_argument("--output","-o",dest="output",type=str,default="report.txt",help="The name of the output file")
parser.add_argument("--title","-t",dest="title",type=str,default="title.txt",help="Print all kasan titles")

args=parser.parse_args()

report=args.reports
output=args.output
title=args.title

if os.path.isfile(report):
    pass
else:
    print(f"[-] {report} is not a file or does not exist")
    exit()
    
    
with open(report,"r") as f:
    datas=f.readlines()


op=open(output,"w")

kasans=dict()

warning_split="=========================================="
KASAN_string="KASAN: use-after-free"
Slab_string="KASAN: slab-use-after-free"

kasan_num=0
num=0

def record_kasan(num:int,datas:list)->bool|int:
    global op
    op.write(datas[num])
    num+=1
    while 1:
        if num==len(datas):
            return False
        op.write(datas[num])
        if warning_split in datas[num]:
            return num
        num+=1
    

while 1:
    if num>=len(datas) or num+1>=len(datas):
        break
    if warning_split in datas[num] and (KASAN_string in datas[num+1] or Slab_string in datas[num+1]):
        alt=num
        while 1:
            if KASAN_string in datas[alt+1] or Slab_string in datas[alt+1]:
                alt+=1
            else:
                break
        names=datas[alt].split(" ")
        name=names[0]+" "+names[1]+" "+names[2]+" "+names[3]+" "+names[4]+'\n'
        if name not in kasans:
            kasans[name]=True
            kasan_num+=1
            res=record_kasan(num,datas)
            if res==False:
                break
            else:
                num=res+1
        else:
            #Assume that a total kasan report should more than 10 lines
            num+=10
    else:
        num+=1
    
op.close()
print(f"[+] {kasan_num} kasans found")

with open(title,"w") as f:
    for k in kasans.keys():
        f.write(k)

print(f"[+] Titles are saved in {title}")
  
        

        
        
    
    