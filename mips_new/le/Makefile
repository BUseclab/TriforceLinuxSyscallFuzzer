CFLAGS= -g -Wall
CC=/opt/mipsel_gcc-4.3/usr/bin/mipsel-linux-gnu-gcc

all : driver

OBJS= aflCall.o driver.o parse.o sysc.o argfd.o
driver: $(OBJS)
	$(CC) $(CFLAGS) -static -o $@ $(OBJS)

clean:
	rm -f $(OBJS) $(HOBJS)
