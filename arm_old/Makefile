CFLAGS= -g
CC=/opt/arm_gcc-3.4/usr/bin/arm-linux-gnueabi-gcc

all : driver

OBJS= aflCall.o driver.o parse.o sysc.o argfd.o
driver: $(OBJS)
	$(CC) $(CFLAGS) -static -o $@ $(OBJS) 
clean:
	rm -f $(OBJS) $(HOBJS)
