#obj-m += seedFilter.o
#obj-m += packet_filter.o
#obj-m += icmp_filter.o
obj-m += telnet_filter.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

ins:
	sudo dmesg -C
	sudo insmod seedFilter.ko

rm:
	sudo rmmod seedFilter