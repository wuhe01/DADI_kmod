overlaybd-y      :=        obd.o 

obj-$(CONFIG_BLK_DEV_RAM)	+=  overlaybd.o

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
