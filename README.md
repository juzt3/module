# n1rip/module

An open-source Linux kernel module that provides APIs to:
- Read and write the memory of any user-space process from the kernel.
- Generate keystrokes or mouse inputs on the system.  

⚠️ **Disclaimer:** This project is made for **educational purposes only**.  

---

## Requirements

Before building, make sure the required tools are installed:

```bash
sudo apt update
sudo apt install make gcc linux-headers-$(uname -r)
```

## Build Instructions

Clone the repository and move into the module directory:

```bash
git clone https://github.com/n1rip/module.git
cd module
```

## Compile
```bash
make
```

## Clean
```bash
make clean
```

## Install
```bash
make install
```

### This will:

Copy n1.ko into /lib/modules/$(uname -r)/extra/

Update module dependencies with depmod

Allow you to load it with:
```bash
sudo modprobe n1
```

## Load it automatically
```bash
echo "n1" | sudo tee /etc/modules-load.d/n1.conf
```
