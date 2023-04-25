CFLAGS= -g -Wall
#CC=mips-linux-gnu-gcc
#CC=mipsel-linux-gnu-gcc
#LD=mipsel-linux-gnu-ld
#CC1=mips-linux-gnu-gcc
#LD1=mips-linux-gnu-ld
#CC2=arm-linux-gnueabi-gcc
#LD2=arm-linux-gnueabi-ld
#CC3=arm-linux-gnu-gcc
#LD=arm-linux-gnu-ld

all : driver_mips_be

OBJS1= driver_poc.o parse.o sysc.o argfd.o
driver_mips_be: $(OBJS1)
	$(CC) $(CFLAGS) -static -o $@ $(OBJS1)

OBJS2= driver_poc.o parse.o sysc.o argfd.o
driver_mips_le: $(OBJS2)
	$(CC) $(CFLAGS) -static -o $@ $(OBJS2)

OBJS3= driver_poc.o parse.o sysc.o argfd.o
driver_arm_new: $(OBJS3)
	$(CC) $(CFLAGS) -static -o $@ $(OBJS3)

OBJS4= driver_poc.o parse.o sysc.o argfd.o
driver_arm_old: $(OBJS4)
	$(CC) $(CFLAGS) -static -o $@ $(OBJS4)

clean:
	rm -f $(OBJS1) $(HOBJS)

