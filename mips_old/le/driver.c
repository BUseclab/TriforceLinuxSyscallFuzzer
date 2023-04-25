/* 
 * Syscall driver
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/ioctl.h> 
#include <bits/ioctls.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/if.h>



#include "drv.h"
#include "sysc.h"

int verbose = 0;
static void usage(char *prog) {
    printf("usage:  %s [-tvx] [-f nr]*\n", prog);
    printf("\t\t-f nr\tFilter out cases that dont make this call. Can be repeated\n");
    printf("\t\t-t\ttest mode, dont use AFL hypercalls\n");
    printf("\t\t-T\tenable qemu's timer in forked children\n");
    printf("\t\t-v\tverbose mode\n");
    printf("\t\t-x\tdon't perform system call\n");
    exit(1);
}

static void watcher(void) {
    int pid, status;

    if((pid = fork()) == 0)
        return;

    waitpid(pid, &status, 0);
    /* if we got here the driver died */
    if (verbose)
    	printf("Inside watcher\n");
    doneWork(0);
    exit(0);
}

unsigned long exec_syscall(struct slice *x[], struct slice *mod_data, int ioctl_num, int *ioctl_arg_num){
	FILE *file;
	int ret;
	int i,j;
	ret = 0;
	int fd;
	unsigned long cmd;
	unsigned long proto, p_family;
	char mdata[2048];
	char fname[64];
	char *cur;
	char case_type[16];
	int test_type;
	struct ifreq ifr;

	if (verbose)
		printf("Filename is %s\n",mod_data[2].cur);
	// Copy the filename to the fname buffer
	ret = snprintf(fname,64,"%s",mod_data[2].cur);
	if (ret < 0){
		printf("Could not print the name in the name buffer\n");
	}
	fname[63] = '\0';

    	memcpy(case_type,mod_data[3].cur,(mod_data[3].end - mod_data[3].cur));
    	/*First type where we have a character device*/
	test_type = strtoul(case_type, 0L, 10);
	if (test_type == 0){
		/*Try to open the file for write first*/
		fd = open(fname, O_RDWR);
		if (fd < 0) {
			printf("Open with read-write failed %s\n", fname);
			fd = open(fname, O_WRONLY);}
		if (fd < 0){
			printf("Open with write failed %s\n", fname);
			fd = open(fname, O_RDONLY);}
		if (fd < 0) {
			printf("\n open() with read failed with error %s\n", fname);
			doneWork(99);
		}
	}
	else if (test_type == 1){
		fd = socket(AF_INET,SOCK_DGRAM,0);
		strncpy(ifr.ifr_name, fname, sizeof(ifr.ifr_name)-1);
		if ((fd = socket(AF_INET, SOCK_DGRAM,0))< 0){
			printf("\n Could not create socket for the network interface %s\n", fname);
			doneWork(99);
		}
		if (verbose)
			printf("Created socket for net device %s\n",fname);
	}
	else if (test_type == 2){
		/*For this case the fname holds the network protocol*/
		proto = strtoul(fname, 0L, 10);
		/*Get the protocol family num*/
		ret = snprintf(mdata,1024,"%s",x[0][0].cur);
		if (ret < 0){
			printf("Could not print the data in the buffer\n");
		}

		// Get the command number
		cmd = strtoul(mdata, 0L, 10);
		
		// Zero out the buffer
		for (j = 0; j < 2048; j++){
			mdata[j] ='\0';
		}
	}

	// For each ioctl we have to run copy the number and contents 
	// and run the ioctl
	//
	for (i = 0; i < ioctl_num; i++){
		if (verbose)
			printf("Copying data for ioctl %d\n",i);

                if (x[i][0].end - x[i][0].cur > 10)
			x[i][0].end = x[i][0].cur + 10;
		
		ret = snprintf(mdata,1024,"%s",x[i][0].cur);
		if (ret < 0){
			printf("Could not print the data in the buffer\n");
		}
    		
		// Get the command number
		cmd = strtoul(mdata, 0L, 10);
		if (verbose)
                	printf("Ioctl: %d got command cmd: %lu\n",i,cmd);

		// Zero out the buffer
		for (j = 0; j < 2048; j++){
			mdata[j] ='\0';
		}
		
		if (ioctl_arg_num[i] > 1){
			if (verbose)
				printf("Copying data of ioctl %d to the data buffer\n",i);
			memcpy(mdata,x[i][1].cur,(x[i][1].end - x[i][1].cur));
		}

		if (verbose)
			printf("Running ioctl number %d\n",i);
		if (test_type == 1){
            memcpy(&ifr + 16,mdata,16);
			ret = ioctl(fd,cmd,&ifr);
		}
		else{
			ret = ioctl(fd,cmd,(void*) mdata);
		}
		if (ret < 0){
			printf("IOCTL returned a negative value\n");
			break;
		}
	}
	/*Run the ioctl*/
	return ret;
}


static int
parseU16(char *p, unsigned short *x)
{
    unsigned long val;
    char *endp;

    val = strtoul(p, &endp, 10);
    if(endp == p || *endp != 0
    || val < 0 || val >= 65536)
        return -1;
    *x = val;
    return 0;
}


int
main(int argc, char **argv)
{
	
    // Initial buffers to get data about the module
    // and the ioctls we have to call
    struct slice slice, dataslice;
    char *prog, *buf, *data;
    char num1[15],num2[15];
    u_long sz;
    u_long datasz;
    long x;
    int opt, nrecs, parseOk,n_mod_data,i,ioctl_data[3];
    int enableTimer = 0;

    unsigned int start_addr = 0;
    unsigned int end_addr = 0;
    
    prog = argv[0];
    
    aflTestMode= 0;
    struct slice ioctlslices[3];
    struct slice *argslices[3];     /*This holds the arguments for the individual ioctls*/
    struct slice modslices[7];
    struct slice ioctl_args[3];

    while((opt = getopt(argc, argv, "tTv")) != -1) {
	switch(opt) {
	case 't':
	    aflTestMode = 1;
	    break;
	case 'T':
	    enableTimer = 1;
	    break;
	case 'v':
	    verbose++;
	    break;
	case '?':
	default:
	    usage(prog);
	    break;
	}
    }
    argc -= optind;
    argv += optind;
    if(argc)
	usage(prog);

    if(!aflTestMode)
	watcher();
	
    startForkserver(1);
 	
    data = getData(&datasz);   // Get the module data from the aflFile2 only once
    if (verbose)
    	printf("Got data: %ld - %.*s\n", datasz, (int)datasz, data);
    
    
    buf = getWork(&sz);
    //printf("Got work: %ld - %.*s\n", sz, (int)sz, buf);
    //extern void __start(), __libc_start_main();
    //startWork((u_long)__start, (u_long)__libc_start_main);
    startWork(0, 0);

    
    /*First get the data about the module: Start and End address and device file name*/
    mkSlice(&dataslice, data, datasz);
    parseOk = parseSysRecArr(&dataslice,2,4,&n_mod_data,modslices);
    if (parseOk != 0){
		printf("Could not parse the data for the module\n");
		doneWork(0);
		return 0;
    }

    /*Get start and end address for the module*/	
    memcpy(num1,modslices[0].cur,(modslices[0].end - modslices[0].cur));
    memcpy(num2,modslices[1].cur,(modslices[1].end - modslices[1].cur));
   
	//Converting strings to numbers
    start_addr = strtoul(num1, 0L, 10);
    end_addr = strtoul(num2, 0L, 10);
   
	/*Get the data for the ioctl*/
    mkSlice(&slice, buf, sz);
    parseOk = parseSysRecArr(&slice,1,3,&nrecs,ioctlslices);
    if (parseOk == 0){
	    for (i =0; i< nrecs; i++){
    		parseOk = parseSysRecArr(&ioctlslices[i],2,2,&ioctl_data[i],&ioctl_args[i]);
		if (parseOk != 0){
			printf("Could not parse the data for IOCTL %d\n",i);
			goto out;
		}
		argslices[i] = &ioctl_args[i];   
	    }
	    parseOk = 0;
    }

    if(parseOk == 0){ //&& filterCalls(filtCalls, nFiltCalls, recs, nrecs) ) {
//	trace kernel code while performing syscalls
	startWork(start_addr, end_addr);
//	note: if this crashes, watcher will do doneWork for us
	x = exec_syscall(argslices,modslices,nrecs,ioctl_data);
	if (verbose) printf("syscall returned %ld\n", x);
    } else {
	if (verbose) printf("Rejected by filter\n");
    }
out:
    fflush(stdout);
    doneWork(0);
    return 0;
}

