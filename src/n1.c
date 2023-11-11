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
#include <asm/page.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/input-event-codes.h>

/**
 * @brief Containing different types of supported input devices
 */
enum n1_input_device_type_e {
    input_device_keyboard,
    input_device_mouse
};

/**
 * @brief Containing different types of supported key states
 */
enum n1_key_state_e {
    key_state_released,
    key_state_pressed
};

/**
 * @brief Containing info about a process
 * @param name Name of the process (In)
 * @param pid Pid of the process (Out)
*/
struct n1_process_s {
    char name[256];
    pid_t pid;
};

/**
 * @brief Contains the info about a memory region
 * @param pid Pid of the process to scan (In)
 * @param name Name of the region (In)
 * @param start Start address of the region (Out)
 * @param end End address of the region (Out)
*/
struct n1_region_s {
    pid_t pid;
    char name[256];
    uintptr_t start;
    uintptr_t end;
};

/**
 * @brief Contains info about a memory request (Read or Write)
 * @param pid Pid of the process to scan (In)
 * @param address Address of the block of memory to read (In)
 * @param len Amount of bytes to read from the address (In)
 * @param buffer_address Address of a buffer containing data for Write operation, empty for Read operation
*/
struct n1_rw_s {
    pid_t pid;
    uintptr_t address;
    size_t len;
    uintptr_t buffer_address;
};

/**
 * @brief Contains info about a input generation event
 * @param code Corresponding key code (see: <linux/input-event-codes.h>)
 * @param value 1 = press, 0 = release
 * @param type Event type
 * @param device_type Device type this input should be sent to
 */
struct n1_input_s {
    int code;
    int value;
    int type;
    enum n1_input_device_type_e device_type;
};

/**
 * @brief Contains info about key state
 * @param code Corresponding key code (see: <linux/input-event-codes.h>)
 * @param state State of the key
 */
struct n1_key_state_s {
    int code;
    enum n1_key_state_e state;
};

/**
 * Ioctl declarations
*/
#define N1_GET_PROCESS _IOWR(0x22, 0, struct n1_process_s *)
#define N1_GET_REGION _IOWR(0x22, 1, struct n1_region_s *)
#define N1_READ _IOWR(0x22, 2, struct n1_rw_s *)
#define N1_WRITE _IOWR(0x22, 3, struct n1_rw_s *)
#define N1_GENERATE_INPUT _IOWR(0x22, 4, struct n1_input_s *)
#define N1_GET_KEY_STATE _IOWR(0x22, 5, struct n1_key_state_s *)

/**
 * Global variables
*/
dev_t dev = 0;
static struct class *dev_class;
static struct cdev n1_cdev;
static struct input_dev *n1_keyboard;
static struct input_dev *n1_mouse;

/**
 * Forward declarations
*/
ssize_t n1_read(struct file *file, char __user *buf, size_t len, loff_t *offp);
ssize_t n1_write(struct file *file, const char __user *buf, size_t len, loff_t *offp);
int n1_open(struct inode *inode, struct file *file);
int n1_release(struct inode *inode, struct file *file);
long int n1_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
void n1_input_event_callback(struct input_handle *handle, unsigned int type, unsigned int code, int value);
int n1_input_connect_callback(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id);
void n1_input_disconnect_callback(struct input_handle *handle);


/**
 * @brief Defines file operations supported by the device
*/
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = n1_read,
    .write = n1_write,
    .open = n1_open,
    .release = n1_release,
    .unlocked_ioctl = n1_ioctl
};

/**
 * @brief Defines the types of input devices and events that the input handler is interested in handling.
 */
static const struct input_device_id n1_input_id_table[] = {
    { .driver_info = 1 },	/* Matches all devices */
	{ }, /* Terminating null entry */
};

/**
 * @brief Handles the input events
 */
static struct input_handler n1_handler = {
	.connect = n1_input_connect_callback,
	.disconnect = n1_input_disconnect_callback,
	.name = "n1",
	.id_table = n1_input_id_table,
};

/**
 * @brief Gets called on input device connection (or detection)
 * @param handler Pointer to managing input_handler struct
 * @param dev Pointer to corresponding input device
 * @param id Pointer to other information concerning the device
 * @return 0 on success
*/
int n1_input_connect_callback(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id)
{
    struct input_handle *handle;
    int status;

    handle = kmalloc(sizeof(struct input_handle), GFP_KERNEL);
    if (!handle) {
        return -ENOMEM;
    }

    handle->dev = dev;
    handle->handler = handler;
    handle->name = NULL;
    handle->private = NULL;

    status = input_register_handle(handle);
    if (status) {
        goto err_free_handle;
    }

    status = input_open_device(handle);
    if (status) {
        goto err_unregister_handle;
    }

    pr_info("n1: input_connect_callback: dev=%s, phys=%s\n", dev->name, dev->phys);

    return 0;

err_unregister_handle:
    input_unregister_handle(handle);

err_free_handle:
    kfree(handle);

    pr_err("n1: failed to handle connect callback for device %s\n", dev->name);

    return status;
}

/**
 * @brief Called on input device disconnection
 * @param handle Handle to the input device, created in spy_connect_callback()
 */
void n1_input_disconnect_callback(struct input_handle *handle)
{
    pr_info("n1: input_disconnect_callback: dev=%s, phys=%s\n", handle->dev->name, handle->dev->phys);

    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
}

/**
 * Finds the process struct by its name
 * @param name Name of the process to find
 * @return Pointer to the process struct, NULL otherwise
*/
static struct task_struct *find_process_by_name(const char *name) {
    struct task_struct *task;

    for_each_process(task) {
        if (!strcmp(task->comm, name)) {
            return task;
        }
    }

    return NULL;
}

/**
 * Reads user-space memory at a certain address
 * @param address Address to read from
 * @param pid Pid of the process to read memory from
 * @param len Length to read (in bytes)
 * @param buffer Buffer that will be filled with read data, should be large enough to contain the data
 * @return Number of bytes read, or error code
 */
ssize_t rw_virtual_memory(uintptr_t address, pid_t pid, size_t len, void* buf, int write) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    void *old_buf;
    int flags;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        return -ESRCH;
    }

	old_buf = buf;
    flags = write ? FOLL_WRITE : 0;

	if (down_read_killable(&mm->mmap_lock)) {
        return -EFAULT;
    }

	while (len) { 
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages_remote(mm, address, 1, flags, &page, NULL);
		if (ret <= 0) {
			vma = vma_lookup(mm, address);

			if (!vma) {
				break;
            }

			if (vma->vm_ops && vma->vm_ops->access) {
				ret = vma->vm_ops->access(vma, address, buf, len, flags);
            }

			if (ret <= 0) {
                break;
            }

			bytes = ret;
		} else { 
			bytes = len;
			offset = address & (PAGE_SIZE-1);

			if (bytes > PAGE_SIZE-offset) {
				bytes = PAGE_SIZE-offset;
            }

			maddr = kmap(page);

			if (write) {
				copy_to_user_page(vma, page, address, maddr + offset, buf, bytes);
				set_page_dirty_lock(page); 
			} else {
				copy_from_user_page(vma, page, address, buf, maddr + offset, bytes);
			}

			kunmap(page);
			put_page(page);
		}

		len -= bytes;
		buf += bytes;
		address += bytes;
	}

	up_read(&mm->mmap_lock);
    mmput(mm);

    return buf - old_buf;
}

/**
 * @brief Generate a mouse input
 * @param device Input device struct
 * @param type Event type (EV_KEY, EV_REL...)
 * @param code Event code (KEY_A, BTN_LEFT, REL_X, REL_Y...)
 * @param value Event value (Key/Button press, movement delta...)
 */
void generate_input(struct input_dev *device, int type, int code, int value) {
    input_event(device, type, code, value);
    input_sync(device);
}

/**
 * @brief Called by input_handler_for_each_handle() function to check a key state
 * @param handle Handle to the input device
 * @param data struct n1_key_state_s containing the key code
 * @return 1 if key is pressed, 0 otherwise
 */
static int check_key_state(struct input_handle *handle, void* data)
{
    struct n1_key_state_s* d = data;

    d->state = test_bit(d->code, handle->dev->key) ? key_state_pressed : key_state_released;

	return d->state;
}

/**
 * Ioctl handler function
 * @param inode File being worked on
 * @param file File pointer
 * @param cmd Ioctl command
 * @param arg Ioctl argument
 * @return 0 on success
*/
long int n1_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch(cmd) {
        case N1_GET_PROCESS: {
            struct n1_process_s req;
            struct task_struct *task;
            int status = 0;

            if (copy_from_user(&req, (void *)arg, sizeof(struct n1_process_s)) != 0) {
                status = -EFAULT;
                goto get_process_out;
            }

            task = find_process_by_name(req.name);
            if (!task) {
                status = -ESRCH;
                goto get_process_out;
            }

            req.pid = task->pid;

            if (copy_to_user((void*)arg, &req, sizeof(struct n1_process_s)) != 0) {
                status = -EFAULT;
                goto get_process_out;
            }

        get_process_out:
            pr_info("n1: get_process: status=%d, name=%s, pid=%d\n", status, status == 0 ? task->comm : "error", status == 0 ? task->pid : 0);

            return status;
        }
        case N1_GET_REGION: {
            struct n1_region_s req;
            struct task_struct *task;
            struct vm_area_struct *vma;
            struct mm_struct *mm;
            int status = 0;

            if (copy_from_user(&req, (void *)arg, sizeof(struct n1_region_s)) != 0) {
                status = -EFAULT;
                goto get_region_out;
            }

            task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
            if (task == NULL) {
                status = -ESRCH;
                goto get_region_out;
            }
            
            mm = get_task_mm(task);
            if (mm == NULL) {
                status = -EINVAL;
                goto get_region_out;
            }

            VMA_ITERATOR(vmi, mm, 0);

            for_each_vma(vmi, vma) {
                if (vma->vm_file == NULL) {
                    continue;
                }

                if (strcmp(vma->vm_file->f_path.dentry->d_name.name, req.name) == 0 && (vma->vm_flags & VM_EXEC)) {
                    break;
                }
            }

            req.start = vma->vm_start;
            req.end = vma->vm_end;
            
            if (copy_to_user((void*)arg, &req, sizeof(struct n1_region_s)) != 0) {
                status = -EFAULT;
                goto get_region_out;
            }

        get_region_out:
            pr_info("n1: get_region: status=%d, name=%s\n", status, status == 0 ? req.name : "error");

            return status;
        }
        case N1_WRITE: {
            struct n1_rw_s req;
            void* temp;
            int status = 0;
            ssize_t written_bytes;

            if (copy_from_user(&req, (void *)arg, sizeof(struct n1_rw_s)) != 0) {
                status = -EFAULT;
                goto write_out;
            }

            pr_info("n1: write_memory: address=0x%px, pid=%d, len=%lu\n", (void*)req.address, req.pid, req.len);

            temp = vmalloc(req.len);
            if (!temp) {
                status = -ENOMEM;
                goto write_out;
            }

            if (copy_from_user(temp, (void*)req.buffer_address, req.len) != 0) {
                status = -EFAULT;
                goto write_out;
            }

            written_bytes = rw_virtual_memory(req.address, req.pid, req.len, temp, 1);
            if (written_bytes < req.len) {
                status = -EAGAIN;
                goto write_out;
            }

        write_out:
            if (temp) {
                vfree(temp);
            }

            pr_info("n1: write_memory: status=%d, written_bytes=%ld/%lu\n", status, written_bytes, req.len);

            return status;
        }
        case N1_READ: {
            struct n1_rw_s req;
            void* temp;
            int status = 0;
            ssize_t read_bytes;

            if (copy_from_user(&req, (void *)arg, sizeof(struct n1_rw_s)) != 0) {
                status = -EFAULT;
                goto read_out;
            }

            pr_info("n1: read_memory: address=0x%px, pid=%d, len=%lu\n", (void*)req.address, req.pid, req.len);

            temp = vmalloc(req.len);
            if (!temp) {
                status = -ENOMEM;
                goto read_out;
            }

            read_bytes = rw_virtual_memory(req.address, req.pid, req.len, temp, 0);
            if (read_bytes < req.len) {
                status = -EAGAIN;
                goto read_out;
            }

            if (copy_to_user((void*)req.buffer_address, temp, req.len) != 0) {
                status = -ENOMEM;
                goto read_out;
            }

            if (copy_to_user((void*)arg, &req, sizeof(struct n1_rw_s)) != 0) {
                status = -ENOMEM;
                goto read_out;
            }

        read_out:
            if (temp) {
                vfree(temp);
            }

            pr_info("n1: read_memory: status=%d, read_bytes=%ld/%lu\n", status, read_bytes, req.len);

            return status;
        }
        case N1_GENERATE_INPUT: {
            struct n1_input_s req;
            int status = 0;

            if (copy_from_user(&req, (void *)arg, sizeof(struct n1_input_s)) != 0) {
                status = -EFAULT;
                goto generate_input_out;
            }

            if (req.device_type == input_device_keyboard) {
                generate_input(n1_keyboard, req.type, req.code, req.value);
            } else {
                generate_input(n1_mouse, req.type, req.code, req.value);
            }

        generate_input_out:
            pr_info("n1: generate_input: status=%d, code=%d, value=%d, type=%d, device=%d\n", status, req.code, req.value, req.type, req.device_type);

            return status;
        }
        case N1_GET_KEY_STATE: {
            struct n1_key_state_s req;
            int status = 0;

            if (copy_from_user(&req, (void *)arg, sizeof(struct n1_key_state_s)) != 0) {
                status = -EFAULT;
                goto get_key_state_out;
            }

            input_handler_for_each_handle(&n1_handler, &req, check_key_state);

            if (copy_to_user((void*)arg, &req, sizeof(struct n1_key_state_s)) != 0) {
                status = -EFAULT;
                goto get_key_state_out;
            }

        get_key_state_out:
            pr_info("n1: get_key_state: status=%d, code=%d, state=%d\n", status, req.code, req.state);

            return status;
        }
        default: {
            pr_info("n1: unknown ioctl\n");
            break;
        }
    }

    return 0;
}

/**
 * Gets called when an application read the device file in /dev/<device name>
 * @param file File pointer
 * @param buf User-space data buffer pointer
 * @param len Size of the requested data transfer
 * @param offp Indicates the file position the user is accessing
 * @return Number of bytes read, Negative value on error
*/
ssize_t n1_read(struct file *file, char __user *buf, size_t len, loff_t *offp) {
    pr_info("n1: read\n");

    return 0;
}

/**
 * Gets called when an application writes to the device file in /dev/<device name>
 * @param file File pointer
 * @param buf User-space data buffer pointer
 * @param len Size of the requested data transfer 
 * @param offp Indicates the file position the user is accessing
 * @return Number of bytes written, Negative value on error
*/
ssize_t n1_write(struct file *file, const char __user *buf, size_t len, loff_t *offp) {
    pr_info("n1: write\n");

    return len;
}

/**
 * Gets called when the device file gets opened
 * @param inode File information
 * @param file File pointer
 * @return 0 on success
*/
int n1_open(struct inode *inode, struct file *file) {
    pr_info("n1: open\n");

    return 0;
}

/**
 * Gets called when the device file gets released 
 * @param inode File information
 * @param file File pointer
 * @return 0 on success
*/
int n1_release(struct inode *inode, struct file *file) {
    pr_info("n1: release\n");
    
    return 0;
}

/**
 * Initialize keyboard device
 * @return 0 on success, -1 otherwise
 */
static int n1_register_keyboard_input_device(void) {
    int status;
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
    if (!n1_keyboard) {
        return -ENOMEM;
    }

    n1_keyboard->name = "n1_keyboard";
    n1_keyboard->phys = "n1/input0";
    n1_keyboard->id.bustype = BUS_USB;
    n1_keyboard->id.vendor = 0x1337;
    n1_keyboard->id.product = 0x1337;
    n1_keyboard->id.version = 0x1337;

    set_bit(EV_KEY, n1_keyboard->evbit);
    for (int i = 0; i <= sizeof(key_codes) / sizeof(key_codes[0]) - 1; i++) {
        set_bit(key_codes[i], n1_keyboard->keybit);
    }

    status = input_register_device(n1_keyboard);
    if (status) {
        input_free_device(n1_keyboard);
        return status;
    }

    pr_info("n1: keyboard initialized: name=%s, phys=%s\n", n1_keyboard->name, n1_keyboard->phys);

    return 0;
}

/**
 * Initialize mouse device
 * @return 0 on success, -1 otherwise
 */
static int n1_register_mouse_input_device(void) {
    int status;
    int button_codes[] = {
        BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA
    };
    int rel_codes[] = {
        REL_X, REL_Y
    };

    n1_mouse = input_allocate_device();
    if (!n1_mouse) {
        return -ENOMEM;
    }

    n1_mouse->name = "n1_mouse";
    n1_mouse->phys = "n1/input1";
    n1_mouse->id.bustype = BUS_USB;
    n1_mouse->id.vendor = 0x1337;
    n1_mouse->id.product = 0x1337;
    n1_mouse->id.version = 0x1337;

    set_bit(EV_KEY, n1_mouse->evbit);
    for (int i = 0; i <= sizeof(button_codes) / sizeof(button_codes[0]) - 1; i++) {
        set_bit(button_codes[i], n1_mouse->keybit);
    }

    set_bit(EV_REL, n1_mouse->evbit);
    for (int i = 0; i <= sizeof(rel_codes) / sizeof(rel_codes[0]) - 1; i++) {
        set_bit(rel_codes[i], n1_mouse->relbit);
    }

    status = input_register_device(n1_mouse);
    if (status) {
        input_free_device(n1_mouse);
        return status;
    }

    pr_info("n1: mouse initialized: name=%s, phys=%s\n", n1_mouse->name, n1_mouse->phys);

    return 0;
}

/**
 * Called by the os on module insertion
 * @return 0 on success, -1 otherwise
*/
static int __init n1_init(void) {
    if (alloc_chrdev_region(&dev, 0, 1, "n1") < 0) {
        pr_err("n1: failed to allocate major number\n");
        return -1;
    }

    cdev_init(&n1_cdev, &fops);

    if(cdev_add(&n1_cdev, dev, 1) < 0){
        pr_err("n1: failed to add the device to the system\n");
        goto class_fail;
    }

    dev_class = class_create("n1");
    if (IS_ERR(dev_class)) {
        pr_err("n1: failed to create struct class for device\n");
        goto class_fail;
    }

    if (IS_ERR(device_create(dev_class, NULL, dev, NULL, "n1"))) {
        pr_err("n1: failed to create the device\n");
        goto device_fail;
    }

	if (input_register_handler(&n1_handler)) {
        pr_err("n1: failed to register input handler\n");
		goto device_fail;
    }

    if (n1_register_keyboard_input_device() != 0) {
        pr_err("n1: failed to create keyboard input device\n");
        goto handler_fail;
    }

    if (n1_register_mouse_input_device() != 0) {
        pr_err("n1: failed to create mouse input device\n");
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

/**
 * Called by OS on module unload event
*/
static void __exit n1_exit(void) {
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