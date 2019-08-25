

KDIR = /lib/modules/`uname -r`/build

all: $(OBJ)
	make -C $(KDIR) M=`pwd`

clean:
	make -C $(KDIR) M=`pwd` clean

test:
	insmod demo-netfilter.ko
	
remove:
	rmmod demo-netfilter