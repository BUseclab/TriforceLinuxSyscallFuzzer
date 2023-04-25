#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "drv.h"
#include "sysc.h"

extern int verbose;

/* internal syscall arg parsing state */
#define NSLICES 7
#define STKSZ 256
struct parseState {
    struct sysRec *calls;
    int ncalls;
    struct slice slices[NSLICES];
    size_t nslices;
};

static int parseArg(struct slice *b, struct parseState *st, u_int32_t *x);

// For the arguments of the ioctl
int parseSysRec(struct slice *b)
{
    struct slice slices[7];
    int i,nslices;

   // chop input into several slices 
    if(getDelimSlices(b, BUFDELIM, sizeof BUFDELIM-1, NSLICES, slices, &nslices) == -1 || nslices < 1)
	return -1;

    b = &slices[0];
    return 0;
}

// For sequencies of ioctls
// If called with the CALLDELIM then we get the sequencies of ioctls
// If called with th BUFDELIM we get the command number and its data argument
int parseSysRecArr(struct slice *b, int delim, int maxRecs, int *nRecs, struct slice *slices)
{
    size_t i, nslices;
    

    if (maxRecs > 7)
	    maxRecs = 7;
    if (delim == 1){
	    if(getDelimSlices(b, CALLDELIM, sizeof(CALLDELIM)-1, maxRecs ,slices, &nslices) == -1)
		return -1;
    }
    else if (delim == 2){
	    if(getDelimSlices(b, BUFDELIM, sizeof(BUFDELIM)-1, maxRecs ,slices, &nslices) == -1)
		return -1;
    }
    
    	
 //   printf("Nslices %d\n",nslices);
    *nRecs = nslices;

    //printf("Code = %u and contents %s\n",*slices[0].cur,slices[1].cur);
	
    return 0;
}

void
showSysRec(struct sysRec *x)
{
    printf("syscall %d (%lx, %lx, %lx, %lx, %lx, %lx)\n", x->nr, (u_long)x->args[0], (u_long)x->args[1], (u_long)x->args[2], (u_long)x->args[3], (u_long)x->args[4], (u_long)x->args[5]);
}

void
showSysRecArr(struct sysRec *x, int n)
{
    int i;

    for(i = 0; i < n; i++)
        showSysRec(x + i);
}

unsigned long
doSysRec(struct sysRec *x)
{
    /* XXX consider doing this in asm so we can use the real syscall entry instead of the syscall() function entry */
    return syscall(x->nr, x->args[0], x->args[1], x->args[2], x->args[3], x->args[4], x->args[5]);
}

unsigned long
doSysRecArr(struct sysRec *x, int n)
{
    unsigned long ret;
    int i;

    ret = 0;
    for(i = 0; i < n; i++)
        ret = doSysRec(x + i);
    return ret;
}
