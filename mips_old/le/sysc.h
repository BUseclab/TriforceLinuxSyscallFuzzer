
#define BUFDELIM "\xa5\xc9"
#define CALLDELIM "\xb7\xe3"


struct sysRec {
    u_int16_t nr;
    u_int32_t args[6];
};

struct sysRec2{
	struct slice slices[3];
};



//int parseSysRec(struct sysRec *calls, int ncalls, struct slice *b, struct sysRec *x);
int parseSysRecArr(struct slice *b, int delim, int maxRecs, int *nRecs, struct slice *slices);
void showSysRec(struct sysRec *x);
void showSysRecArr(struct sysRec *x, int n);
unsigned long doSysRec(struct sysRec *x);
unsigned long doSysRecArr(struct sysRec *x, int n);

int getStdFile(int typ);

