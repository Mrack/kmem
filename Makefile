CLANG_PATH := /home/mrack/clangx
export PATH := ${CLANG_PATH}/bin:${PATH}

$(warning ${PATH})
MODULE_NAME := kmem
RESMAN_CORE_OBJS:=entry.o
RESMAN_GLUE_OBJS:=

CROSS_COMPILE = ${CLANG_PATH}/bin/aarch64-linux-gnu-
CROSS_COMPILE32 = ${CLANG_PATH}/bin/arm-linux-gnueabi-

ifneq ($(KERNELRELEASE),)    
	$(MODULE_NAME)-objs:=$(RESMAN_GLUE_OBJS) $(RESMAN_CORE_OBJS)
	obj-m := kmem.o
else
	KDIR := /home/mrack/Desktop/android_kernel_xiaomi_marble/out
all:
	make CC=clang CXX=clang++ LLVM=1 LLVM_IAS=1 -C $(KDIR) M=$(PWD) ARCH=arm64 SUBARCH=arm64 modules
	rm -f *.o *.mod.o *.mod.c *.symvers *.order .*.cmd *.mod
install:
	adb push kmem.ko /data/local/tmp
	adb shell su -c "rmmod /data/local/tmp/kmem.ko"
	adb shell su -c "insmod /data/local/tmp/kmem.ko"
clean:    
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order .*.cmd *.mod
endif    
