obj-m += src/n1.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
MODNAME := n1.ko

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	@echo "Installing $(MODNAME) into /lib/modules/$(shell uname -r)/extra/"
	sudo mkdir -p /lib/modules/$(shell uname -r)/extra
	sudo cp src/$(MODNAME) /lib/modules/$(shell uname -r)/extra/
	sudo depmod -a
	@echo "Installation complete. You can load it with: sudo modprobe n1"
