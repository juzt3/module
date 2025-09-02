#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/input.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/input-event-codes.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <asm/page.h>
#include <asm/io.h>

/* Tipos */
enum n1_input_device_type_e { input_device_keyboard, input_device_mouse };
enum n1_key_state_e { key_state_released, key_state_pressed };

/* Estructuras */
struct n1_process_s { char name[256]; pid_t pid; };
struct n1_region_s { pid_t pid; char name[256]; uintptr_t start; uintptr_t end; };
struct n1_rw_s { pid_t pid; uintptr_t address; size_t len; uintptr_t buffer_address; };
struct n1_input_s { int code; int value; int type; enum n1_input_device_type_e device_type; };
struct n1_key_state_s { int code; enum n1_key_state_e state; };

/* Ioctl */
#define N1_GET_PROCESS      _IOWR(0x22, 0, struct n1_process_s *)
#define N1_GET_REGION       _IOWR(0x22, 1, struct n1_region_s *)
#define N1_READ             _IOWR(0x22, 2, struct n1_rw_s *)
#define N1_WRITE            _IOWR(0x22, 3, struct n1_rw_s *)
#define N1_GENERATE_INPUT   _IOWR(0x22, 4, struct n1_input_s *)
#define N1_GET_KEY_STATE    _IOWR(0x22, 5, struct n1_key_state_s *)

/* Globales */
dev_t dev = 0;
static struct class *dev_class;
static struct cdev n1_cdev;
static struct input_dev *n1_keyboard;
static struct input_dev *n1_mouse;

/* FWD decls */
ssize_t n1_read(struct file *file, char __user *buf, size_t len, loff_t *offp);
ssize_t n1_write(struct file *file, const char __user *buf, size_t len, loff_t *offp);
int n1_open(struct inode *inode, struct file *file);
int n1_release(struct inode *inode, struct file *file);
long n1_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int n1_input_connect_callback(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id);
void n1_input_disconnect_callback(struct input_handle *handle);

/* fops */
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = n1_read,
    .write = n1_write,
    .open = n1_open,
    .release = n1_release,
    .unlocked_ioctl = n1_ioctl
};

/* Input handler */
static const struct input_device_id n1_input_id_table[] = {
    { .driver_info = 1 }, /* todos */
    { }
};

static struct input_handler n1_handler = {
    .connect = n1_input_connect_callback,
    .disconnect = n1_input_disconnect_callback,
    .name = "n1",
    .id_table = n1_input_id_table,
};

/* Buscar proceso por nombre (opcional) */
static struct task_struct *find_process_by_name(const char *name) {
    struct task_struct *task;
    for_each_process(task) {
        if (!strcmp(task->comm, name))
            return task;
    }
    return NULL;
}

/* Conexión input */
int n1_input_connect_callback(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id)
{
    struct input_handle *handle;
    int status;

    handle = kzalloc(sizeof(*handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;

    handle->dev = dev;
    handle->handler = handler;
    handle->name = NULL;
    handle->private = NULL;

    status = input_register_handle(handle);
    if (status)
        goto err_free;

    status = input_open_device(handle);
    if (status)
        goto err_unreg;

    // pr_info("n1: input_connect_callback: dev=%s, phys=%s\n", dev->name, dev->phys ? dev->phys : "(none)");
    return 0;

err_unreg:
    input_unregister_handle(handle);
err_free:
    kfree(handle);
    pr_err("n1: failed connect for device %s\n", dev->name);
    return status;
}

/* Desconexión input */
void n1_input_disconnect_callback(struct input_handle *handle)
{
    // pr_info("n1: input_disconnect_callback: dev=%s, phys=%s\n",
    //    handle->dev->name, handle->dev->phys ? handle->dev->phys : "(none)");
    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
}

/* Leer/escribir memoria de usuario de otro proceso - ACTUALIZADO para kernel 6.14 */
static ssize_t rw_virtual_memory(uintptr_t address, pid_t pid, size_t len, void *buf, int write)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma = NULL;
    void *old_buf = buf;
    unsigned int gup_flags = write ? FOLL_WRITE : 0;
    VMA_ITERATOR(vmi, NULL, address);

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    if (!mm)
        return -ESRCH;

    /* Actualizado: usar vma_iterator en lugar de mmap_lock */
    vma_iter_init(&vmi, mm, address);
    mmap_read_lock(mm);

    while (len) {
        int bytes, ret, offset;
        void *maddr;
        struct page *page = NULL;

        /* get_user_pages_remote - signature actualizada para 6.14 */
        ret = get_user_pages_remote(mm, address, 1, gup_flags, &page, NULL);
        if (ret <= 0) {
            /* si falla, intenta vía vm_ops->access */
            vma = vma_lookup(mm, address);
            if (!vma)
                break;

            if (vma->vm_ops && vma->vm_ops->access) {
                ret = vma->vm_ops->access(vma, address, buf, len, gup_flags);
            }
            if (ret <= 0)
                break;

            bytes = ret;
        } else {
            bytes = len;
            offset = address & (PAGE_SIZE - 1);
            if (bytes > PAGE_SIZE - offset)
                bytes = PAGE_SIZE - offset;

            /* Kernel 6.14 ya no usa kmap/kunmap para páginas normales */
            maddr = page_address(page);
            if (!maddr) {
                /* Solo usar kmap_local_page si page_address falla */
                maddr = kmap_local_page(page);
                if (write) {
                    copy_to_user_page(vma, page, address, maddr + offset, buf, bytes);
                    set_page_dirty_lock(page);
                } else {
                    copy_from_user_page(vma, page, address, buf, maddr + offset, bytes);
                }
                kunmap_local(maddr);
            } else {
                if (write) {
                    copy_to_user_page(vma, page, address, maddr + offset, buf, bytes);
                    set_page_dirty_lock(page);
                } else {
                    copy_from_user_page(vma, page, address, buf, maddr + offset, bytes);
                }
            }
            put_page(page);
        }

        len     -= bytes;
        buf     += bytes;
        address += bytes;
    }

    mmap_read_unlock(mm);
    mmput(mm);

    return (ssize_t)(buf - old_buf);
}

/* Generar input */
static void generate_input(struct input_dev *device, int type, int code, int value)
{
    input_event(device, type, code, value);
    input_sync(device);
}

/* Para N1_GET_KEY_STATE */
static int check_key_state(struct input_handle *handle, void *data)
{
    struct n1_key_state_s *d = data;
    d->state = test_bit(d->code, handle->dev->key) ? key_state_pressed : key_state_released;
    return d->state;
}

/* IOCTL */
long n1_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case N1_GET_PROCESS: {
        struct n1_process_s req;
        struct task_struct *task;
        int status = 0;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)) != 0) {
            status = -EFAULT;
            // pr_info("n1: get_process: copy_from_user failed\n");
            return status;
        }

        task = find_process_by_name(req.name);
        if (!task) {
            status = -ESRCH;
        } else {
            req.pid = task->pid;
            if (copy_to_user((void __user *)arg, &req, sizeof(req)) != 0)
                status = -EFAULT;
        }

        // pr_info("n1: get_process: status=%d, name=%s, pid=%d\n",
        //        status, status == 0 ? task->comm : req.name, status == 0 ? task->pid : -1);
        return status;
    }
    case N1_GET_REGION: {
        struct n1_region_s req;
        struct task_struct *task;
        struct mm_struct *mm;
        struct vm_area_struct *vma;
        VMA_ITERATOR(vmi, NULL, 0);
        int status = 0;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)) != 0)
            return -EFAULT;

        task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
        if (!task)
            return -ESRCH;

        mm = get_task_mm(task);
        if (!mm)
            return -EINVAL;

        /* Actualizado: usar VMA iterator en lugar de recorrer mm->mmap */
        vma_iter_init(&vmi, mm, 0);
        mmap_read_lock(mm);

        req.start = 0;
        req.end = 0;

        for_each_vma(vmi, vma) {
            if (!vma->vm_file)
                continue;
            if ((vma->vm_flags & VM_EXEC) &&
                strcmp(vma->vm_file->f_path.dentry->d_name.name, req.name) == 0) {
                req.start = vma->vm_start;
                req.end = vma->vm_end;
                break;
            }
        }

        mmap_read_unlock(mm);
        mmput(mm);

        if (req.start == 0 && req.end == 0)
            status = -ENOENT;

        if (copy_to_user((void __user *)arg, &req, sizeof(req)) != 0)
            status = -EFAULT;

        // pr_info("n1: get_region: status=%d, name=%s, start=0x%px end=0x%px\n",
        //        status, req.name, (void *)req.start, (void *)req.end);
        return status;
    }
    case N1_WRITE: {
        struct n1_rw_s req;
        void *temp = NULL;
        int status = 0;
        ssize_t written_bytes = 0;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)) != 0)
            return -EFAULT;

        // pr_info("n1: write_memory: address=0x%px, pid=%d, len=%lu\n",
        //        (void *)req.address, req.pid, (unsigned long)req.len);

        temp = vmalloc(req.len);
        if (!temp)
            return -ENOMEM;

        if (copy_from_user(temp, (void __user *)req.buffer_address, req.len) != 0) {
            status = -EFAULT;
            goto w_out;
        }

        written_bytes = rw_virtual_memory(req.address, req.pid, req.len, temp, 1);
        if (written_bytes < (ssize_t)req.len)
            status = -EAGAIN;

w_out:
        if (temp)
            vfree(temp);

        // pr_info("n1: write_memory: status=%d, written=%ld/%lu\n",
        //        status, (long)written_bytes, (unsigned long)req.len);
        return status;
    }
    case N1_READ: {
        struct n1_rw_s req;
        void *temp = NULL;
        int status = 0;
        ssize_t read_bytes = 0;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)) != 0)
            return -EFAULT;

        // pr_info("n1: read_memory: address=0x%px, pid=%d, len=%lu\n",
        //        (void *)req.address, req.pid, (unsigned long)req.len);

        temp = vmalloc(req.len);
        if (!temp)
            return -ENOMEM;

        read_bytes = rw_virtual_memory(req.address, req.pid, req.len, temp, 0);
        if (read_bytes < (ssize_t)req.len) {
            status = -EAGAIN;
            goto r_out;
        }

        if (copy_to_user((void __user *)req.buffer_address, temp, req.len) != 0) {
            status = -EFAULT;
            goto r_out;
        }

        if (copy_to_user((void __user *)arg, &req, sizeof(req)) != 0) {
            status = -EFAULT;
            goto r_out;
        }

r_out:
        if (temp)
            vfree(temp);

        // pr_info("n1: read_memory: status=%d, read=%ld/%lu\n",
        //        status, (long)read_bytes, (unsigned long)req.len);
        return status;
    }
    case N1_GENERATE_INPUT: {
        struct n1_input_s req;
        int status = 0;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)) != 0)
            return -EFAULT;

        if (req.device_type == input_device_keyboard)
            generate_input(n1_keyboard, req.type, req.code, req.value);
        else
            generate_input(n1_mouse, req.type, req.code, req.value);

        // pr_info("n1: generate_input: status=%d, code=%d, value=%d, type=%d, device=%d\n",
        //        status, req.code, req.value, req.type, req.device_type);
        return status;
    }
    case N1_GET_KEY_STATE: {
        struct n1_key_state_s req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)) != 0)
            return -EFAULT;

        input_handler_for_each_handle(&n1_handler, &req, check_key_state);

        if (copy_to_user((void __user *)arg, &req, sizeof(req)) != 0)
            return -EFAULT;

        // pr_info("n1: get_key_state: code=%d, state=%d\n", req.code, req.state);
        return 0;
    }
    default:
        // pr_info("n1: unknown ioctl cmd=%u\n", cmd);
        return -ENOTTY;
    }
}

/* fops básicos */
ssize_t n1_read(struct file *file, char __user *buf, size_t len, loff_t *offp)
{
    // pr_info("n1: read\n");
    return 0;
}
ssize_t n1_write(struct file *file, const char __user *buf, size_t len, loff_t *offp)
{
    // pr_info("n1: write\n");
    return len;
}
int n1_open(struct inode *inode, struct file *file)
{
    // pr_info("n1: open\n");
    return 0;
}
int n1_release(struct inode *inode, struct file *file)
{
    // pr_info("n1: release\n");
    return 0;
}

/* Registrar teclado */
static int n1_register_keyboard_input_device(void)
{
    int status, i;
    int key_codes[] = {
        KEY_Q, KEY_W, KEY_E, KEY_R, KEY_T, KEY_Y, KEY_U, KEY_I, KEY_O, KEY_P,
        KEY_A, KEY_S, KEY_D, KEY_F, KEY_G, KEY_H, KEY_J, KEY_K, KEY_L,
        KEY_Z, KEY_X, KEY_C, KEY_V, KEY_B, KEY_N, KEY_M,
        KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7, KEY_8, KEY_9, KEY_0,
        KEY_SPACE, KEY_TAB, KEY_ESC, KEY_ENTER,
        KEY_LEFTSHIFT, KEY_RIGHTSHIFT, KEY_LEFTCTRL, KEY_RIGHTCTRL,
        KEY_LEFTALT, KEY_RIGHTALT, KEY_CAPSLOCK,
        KEY_GRAVE, KEY_MINUS, KEY_EQUAL, KEY_BACKSPACE,
        KEY_LEFTBRACE, KEY_RIGHTBRACE, KEY_BACKSLASH,
        KEY_SEMICOLON, KEY_APOSTROPHE, KEY_COMMA, KEY_DOT, KEY_SLASH,
        KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5, KEY_F6, KEY_F7, KEY_F8, KEY_F9, KEY_F10, KEY_F11, KEY_F12,
        KEY_INSERT, KEY_DELETE, KEY_HOME, KEY_END, KEY_PAGEUP, KEY_PAGEDOWN,
        KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT
    };

    n1_keyboard = input_allocate_device();
    if (!n1_keyboard)
        return -ENOMEM;

    n1_keyboard->name = "n1_keyboard";
    n1_keyboard->phys = "n1/input0";
    n1_keyboard->id.bustype = BUS_USB;
    n1_keyboard->id.vendor  = 0x1337;
    n1_keyboard->id.product = 0x1337;
    n1_keyboard->id.version = 0x1337;

    set_bit(EV_KEY, n1_keyboard->evbit);
    for (i = 0; i < (int)(sizeof(key_codes) / sizeof(key_codes[0])); i++)
        set_bit(key_codes[i], n1_keyboard->keybit);

    status = input_register_device(n1_keyboard);
    if (status) {
        input_free_device(n1_keyboard);
        return status;
    }

    // pr_info("n1: keyboard initialized: name=%s, phys=%s\n", n1_keyboard->name, n1_keyboard->phys);
    return 0;
}

/* Registrar mouse */
static int n1_register_mouse_input_device(void)
{
    int status, i;
    int button_codes[] = { BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA };
    int rel_codes[]    = { REL_X, REL_Y };

    n1_mouse = input_allocate_device();
    if (!n1_mouse)
        return -ENOMEM;

    n1_mouse->name = "n1_mouse";
    n1_mouse->phys = "n1/input1";
    n1_mouse->id.bustype = BUS_USB;
    n1_mouse->id.vendor  = 0x1337;
    n1_mouse->id.product = 0x1337;
    n1_mouse->id.version = 0x1337;

    set_bit(EV_KEY, n1_mouse->evbit);
    for (i = 0; i < (int)(sizeof(button_codes) / sizeof(button_codes[0])); i++)
        set_bit(button_codes[i], n1_mouse->keybit);

    set_bit(EV_REL, n1_mouse->evbit);
    for (i = 0; i < (int)(sizeof(rel_codes) / sizeof(rel_codes[0])); i++)
        set_bit(rel_codes[i], n1_mouse->relbit);

    status = input_register_device(n1_mouse);
    if (status) {
        input_free_device(n1_mouse);
        return status;
    }

    // pr_info("n1: mouse initialized: name=%s, phys=%s\n", n1_mouse->name, n1_mouse->phys);
    return 0;
}

/* init - ACTUALIZADO para kernel 6.14 */
static int __init n1_init(void)
{
    if (alloc_chrdev_region(&dev, 0, 1, "n1") < 0) {
        // pr_err("n1: failed to allocate major number\n");
        return -1;
    }

    cdev_init(&n1_cdev, &fops);
    if (cdev_add(&n1_cdev, dev, 1) < 0) {
        // pr_err("n1: cdev_add failed\n");
        goto class_fail;
    }

    /* Actualizado: class_create sin THIS_MODULE */
    dev_class = class_create("n1");
    if (IS_ERR(dev_class)) {
        // pr_err("n1: class_create failed\n");
        goto class_fail;
    }

    if (IS_ERR(device_create(dev_class, NULL, dev, NULL, "n1"))) {
        // pr_err("n1: device_create failed\n");
        goto device_fail;
    }

    if (input_register_handler(&n1_handler)) {
        // pr_err("n1: input_register_handler failed\n");
        goto device_fail;
    }

    if (n1_register_keyboard_input_device() != 0) {
        // pr_err("n1: keyboard init failed\n");
        goto handler_fail;
    }

    if (n1_register_mouse_input_device() != 0) {
        // pr_err("n1: mouse init failed\n");
        goto mouse_fail;
    }

    pr_info("n1: loaded: major=%d, minor=%d\n", MAJOR(dev), MINOR(dev));
    return 0;

mouse_fail:
    input_unregister_device(n1_keyboard);
handler_fail:
    input_unregister_handler(&n1_handler);
device_fail:
    device_destroy(dev_class, dev);
class_fail:
    unregister_chrdev_region(dev, 1);
    return -1;
}

/* exit */
static void __exit n1_exit(void)
{
    input_unregister_device(n1_mouse);
    input_unregister_device(n1_keyboard);
    input_unregister_handler(&n1_handler);
    device_destroy(dev_class, dev);
    class_destroy(dev_class);
    unregister_chrdev_region(dev, 1);
    pr_info("n1: unloaded\n");
}

module_init(n1_init);
module_exit(n1_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mystère <contact@myst.re>");
MODULE_DESCRIPTION("n1 kernel module");
MODULE_VERSION("1.0.0");