MODULE_NAME = DUKPT_Originator_module

SRCS = DUKPT_Originator.c DES.c DUKPT.c TDES.c

OBJS = $(SRCS:.c=.o)

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-y = $(OBJS)


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


