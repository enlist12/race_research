#!/bin/sh

python3 is_con_uaf.py -i ../angr_linux/test_dir/bullseye.img -r ../angr_linux/test_dir/bullseye.id_rsa -p ../CVEs/syzbot3/poc -b ../CVEs/syzbot3/bzImage -n 6 -o -t 200
