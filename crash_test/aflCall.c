/*
 * AFL hypercalls
 *
 * Compile with -DTEST to take inputs from stdin without using hypercalls.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include "drv.h"
#include <sys/types.h>

int aflTestMode = 0;

#define SZ 4096
#define SZ2 2048
static u_long bufsz;
static char *buf;
static u_int32_t *arr;

static u_long datasz;   // will be used solely for module data
static char *data;

static void
aflInit(void)
{
    static int aflInit = 0;
    char *pg;
    char *pg2;

    if(aflInit)
        return;

    pg = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if(pg == (void*)-1) {
        perror("mmap");
        exit(1);
    }
    memset(pg, 0, SZ); // touch all the bits!

    pg2 = mmap(NULL, SZ2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if(pg2 == (void*)-1) {
        perror("mmap");
        exit(1);
    }

    memset(pg2, 0, SZ2); // touch all the bits!
    
    arr = (u_int32_t *)pg;
    buf = pg + 4 * sizeof arr[0];
    bufsz = SZ - 4 * sizeof arr[0];

    data = pg2;
    datasz = SZ2;
    
    aflInit = 1;
}

static inline u_long
aflCall(u_long a0, u_long a1, u_long a2)
{
    u_long ret;
    asm(".byte 0x28, 0x50, 0x09, 0x01" 
            : "=d"(ret) 
            : "r"(a0), "r"(a1), "r"(a2)
            );
    return ret;
}

int
startForkserver(int ticks)
{
    aflInit();
    if(aflTestMode)
        return 0;
    return aflCall(1, ticks, 0);
}

char *
getWork(u_long *sizep)
{
    aflInit();
    if(aflTestMode)
        *sizep = read(0, buf, bufsz);
    else
        *sizep = aflCall(2, (u_long)buf, bufsz);
    return buf;
}

char *
getData(u_long *sizep)
{
    aflInit();
    if(aflTestMode)
        *sizep = read(0, buf, bufsz);
    else
        *sizep = aflCall(5, (u_long)data, datasz);
    return data;
}

/* buf should point to u_int64_t[2] */
int
startWork(u_int32_t start, u_int32_t end)
{
    aflInit();
    if(aflTestMode)
        return 0;
    arr[0] = start;
    arr[1] = 0;
    arr[2] = end;
    arr[3] = 0;
    return aflCall(3, (u_long)arr, 0);
}

int
doneWork(int val)
{
    aflInit();
    if(aflTestMode)
        return 0;
    return aflCall(4, (u_long)val, 0);
}


int
addNetwork(void)
{
	aflInit();
	return aflCall(6,0,0);
}
