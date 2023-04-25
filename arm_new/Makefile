CFLAGS= -g
CC=/opt/arm_gcc-4.3/usr/bin/arm-linux-gnueabi-gcc
all : driver

OBJS= aflCall.o driver.o parse.o sysc.o argfd.o
driver: $(OBJS)
	$(CC) $(CFLAGS) -static -o $@ $(OBJS) 
clean:
	rm -f $(OBJS) $(HOBJS)
