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

void 
clean_exit_on_sig(int sig_num)
{
        printf ("\n Signal %d received",sig_num);
	exit(11);
}

#include "drv.h"
#include "sysc.h"

static void usage(char *prog) {
    printf("usage:  %s [-tvx] [-f nr]*\n", prog);
    printf("\t\t-f nr\tFilter out cases that dont make this call. Can be repeated\n");
    printf("\t\t-t\ttest mode, dont use AFL hypercalls\n");
    printf("\t\t-T\tenable qemu's timer in forked children\n");
    printf("\t\t-v\tverbose mode\n");
    printf("\t\t-x\tdon't perform system call\n");
    exit(1);
}


unsigned long exec_syscall(struct slice *x[], char *fname, int ioctl_num, int *ioctl_arg_num){
	FILE *file;
	int ret;
	int i,j;
	ret = 0;
	int fd;
	unsigned long cmd;
	unsigned long proto, p_family;
	char mdata[4096];
	char *cur;
	char case_type[16];
	struct ifreq ifr;
	
	for (j = 0; j < 4096; j++){
		mdata[j] ='\0';
	}
	
	printf("Filename is %s\n",fname);

	/*Try to open the file for write first*/
	fd = open(fname, O_RDWR);
	if (fd < 0) {
		printf("Open with read-write failed\n");
		fd = open(fname, O_WRONLY);}
	if (fd < 0){
		printf("Open with write failed\n");
		fd = open(fname, O_RDONLY);}
	if (fd < 0) {
		printf("\n open() with read failed with error\n");
		exit(99);
	}
	
	// For each ioctl we have to run copy the number and contents 
	// and run the ioctl
	//
	for (i = 0; i < ioctl_num; i++){
		printf("Running ioctl number %d\n",i);
		if (x[i][0].end - x[i][0].cur > 10)
			x[i][0].end = x[i][0].cur + 10;
		
		if (x[i][0].end - x[i][0].cur > 2048)
			x[i][0].end = x[i][0].cur + 2048;

		// Copy the cmd number to the buffer
		ret = snprintf(mdata,1024,"%s",x[i][0].cur);
		if (ret < 0){
			printf("Could not print the data in the buffer\n");
		}
		
		// Get the command number
		cmd = strtoul(mdata, 0L, 10);
		printf("Ioctl: %d cmd: %d\n",i,cmd);
 		sleep(2);                
		// Zero out the buffer
		for (j = 0; j < 4096; j++){
			mdata[j] ='\0';
		}
		
		if (ioctl_arg_num[i] > 1){
			printf("Copying data of ioctl %d to the data buffer\n",i);
			memcpy(mdata,x[i][1].cur,(x[i][1].end - x[i][1].cur));
		}

		printf("DATA of ioctl %d\n",i);
		sleep(2);
                
		for (j=0; j < x[i][1].end - x[i][1].cur; j++)
                     printf("%02X",mdata[j]);
        printf("\n");	
                
		sleep(2);
		ret = ioctl(fd,cmd,(void*) mdata);
		sleep(2);
		
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

int verbose = 0;

int
main(int argc, char **argv)
{
	
    // Initial buffers to get data about the module
    // and the ioctls we have to call
    struct slice slice, dataslice;
    char *prog, *buf, *data;
    char num1[15],num2[15];
    u_long sz;
    int temp;
    long x;
    int opt, nrecs, parseOk,n_mod_data,i,ioctl_data[3];
    int enableTimer = 0;

    char the_buffer[2048];
    unsigned int start_addr = 0;
    unsigned int end_addr = 0;
    
    prog = argv[0];
    
    struct slice ioctlslices[3];
    struct slice *argslices[3];     /*This holds the arguments for the individual ioctls*/
    struct slice modslices[7];
    struct slice ioctl_args[3];
    FILE *f;
	
    signal(SIGSEGV, clean_exit_on_sig);
	
    printf("Running ioctl test\n");   	
    f=fopen(argv[2],"rb");
    fseek(f,0,SEEK_END);
    sz = ftell(f);
    rewind(f);
    
    if (sz > 2048)
         sz = 2048;

    fread(&the_buffer,1,sz,f);

    mkSlice(&slice, &the_buffer, sz);
    parseOk = parseSysRecArr(&slice,1,3,&nrecs,ioctlslices);
    if (parseOk == 0){
	    for (i =0; i< nrecs; i++){
    		parseOk = parseSysRecArr(&ioctlslices[i],2,2,&temp,&ioctl_args[i]);
		if (parseOk != 0){
			printf("Could not parse the data for IOCTL %d\n",i);
			goto out;
		}
                ioctl_data[i] = temp;
		argslices[i] = &ioctl_args[i];   
	    }
	    parseOk = 0;
    }
	
    printf("Number of ioctl calls %d\n",nrecs);
    if(parseOk == 0){
	x = exec_syscall(argslices,argv[1],nrecs,ioctl_data);
	if (verbose) printf("syscall returned %ld\n", x);
    } else {
	if (verbose) printf("Rejected by filter\n");
    }
out:
    fflush(stdout);
    return 0;
}

