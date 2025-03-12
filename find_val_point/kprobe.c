#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/version.h>

static int target_pgid;
module_param(target_pgid, int, 0);

/* Kprobe handlers */
static struct kprobe kp_kfree;
static struct kprobe kp_kmem_cache_free;

/* kprobe 处理函数 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {

    if (task_pgrp_nr(current) != target_pgid)
        return 0;
    
    struct pt_regs *task_regs = task_pt_regs(current);
    if (!task_regs)  // 如果没有有效的 pt_regs，跳过
        return 0;

    if(strcmp(p->symbol_name, "kfree") == 0) {
        void *freed_object = (void *)regs->di;  
        long syscall_num = task_regs->orig_ax;
        pr_info("[KPROBE] %s: Freed object at %px, syscall: %ld\n", 
                p->symbol_name, freed_object, syscall_num);
        return 0;
        }
    else if(strcmp(p->symbol_name, "kmem_cache_free") == 0) {
        void *freed_object = (void *)regs->si;  
        long syscall_num = task_regs->orig_ax;
        pr_info("[KPROBE] %s: Freed object at %px, syscall: %ld\n", 
                p->symbol_name, freed_object, syscall_num);
        return 0;
        }
    else {
        pr_err("[KPROBE] Unknown kprobe handler\n");
        return -1;
    }
    return 0;
}


static int __init kprobe_init(void) {
    int ret;
    kp_kfree.symbol_name = "kfree";
    kp_kfree.pre_handler = handler_pre;
    ret = register_kprobe(&kp_kfree);
    if (ret < 0) {
        pr_err("Failed to register kprobe for kfree\n");
        return ret;
    }
    kp_kmem_cache_free.symbol_name = "kmem_cache_free";
    kp_kmem_cache_free.pre_handler = handler_pre;
    ret = register_kprobe(&kp_kmem_cache_free);
    if (ret < 0) {
        pr_err("Failed to register kprobe for kmem_cache_free\n");
        unregister_kprobe(&kp_kfree);
        return ret;
    }

    pr_info("Kprobe module loaded: monitoring kfree and kmem_cache_free\n");
    return 0;
}

/* 退出模块 */
static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp_kfree);
    unregister_kprobe(&kp_kmem_cache_free);
    pr_info("Kprobe module unloaded\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("haoqiguai");
MODULE_DESCRIPTION("Kprobe module for tracking memory free operations and syscalls");
