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

#include <asm/cpu.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pgtable-types.h>

#define OP_CMD_READ 0x400011
#define OP_CMD_WRITE 0x400012
#define OP_CMD_LISTMAP 0x400013

typedef struct _MEMORY
{
    pid_t pid;
    uintptr_t addr;
    void __user *buffer;
    size_t size;
} st_mem;

typedef struct _VMAP
{
    unsigned long start;
    unsigned long end;
    char path[256];
} st_vm;

#define DEVICE_NAME "kmem"
#define TAG "kmem_log: "

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

static struct mm_struct *get_pid_mm(int pid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return NULL;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
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

static int list_vma(struct seq_file *m, pid_t pid)
{
    struct vm_area_struct *vma;
    unsigned long start, end, flag;
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
        flag = vma->vm_flags;

        if (file)
        {
            memset(path_buf, 0, sizeof(path_buf));
            path = d_path(&file->f_path, path_buf, sizeof(path_buf));
            if (path)
            {
                seq_printf(m, "%llx,%llx,%ld,%s\n", start, end, flag, path);
            }
        }
        else
        {
            seq_printf(m, "%llx,%llx,%ld\n", start, end, flag);
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

static int my_seq_show(struct seq_file *m, void *v)
{
    pid_t pid = (pid_t)(uintptr_t)m->private;
    list_vma(m, pid);
    return 0;
}

int my_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, my_seq_show, PDE_DATA(inode));
}

static const struct proc_ops my_proc_ops = {
    .proc_open = my_seq_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = seq_release,
};

struct proc_dir_entry *base;

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    static st_mem mem;
    char mypid[13];
    pr_info(TAG "ioctl\n");

    if (copy_from_user(&mem, (void *__user)arg, sizeof(st_mem)) != 0)
    {
        return -2;
    }

    switch (cmd)
    {
    case OP_CMD_READ:
        return read_mem(mem);
    case OP_CMD_WRITE:
        return write_mem(mem);
    case OP_CMD_LISTMAP:
        snprintf(mypid, 12, "%d", mem.pid);
        proc_create_data(mypid, 0644, base, &my_proc_ops, (void *)((uintptr_t)mem.pid));
        return 0;
    default:
        break;
    }
    return -EINVAL;
}

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
    ret = misc_register(&dev);
    base = proc_mkdir(DEVICE_NAME, NULL);
    return ret;
}

static void __exit driver_unload(void)
{
    pr_info(TAG "driver_unload\n");
    misc_deregister(&dev);
    proc_remove(base);
    return;
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mrack");