#!/usr/bin/env python
"""
Generate syscall input files in the driver's file format.
"""
import struct, sys, subprocess,random

BUFDELIM = "\xa5\xc9"
CALLDELIM = "\xb7\xe3"

#BUFDELIM = "\xc9\xa5"
#CALLDELIM = "\xe3\xb7"

class Buf(object) :
    def __init__(self) :
        self.buf = []
        self.pos = 0
    def add(self, x) :
        #print repr(self), 'add', x.encode('hex')
        self.buf.append(x)
    def pack(self, fmt, *args) :
        x = struct.pack(fmt, *args)
        self.add(x)
    def __str__(self) :
        return ''.join(self.buf)

class Num(object) :
    def __init__(self, v) :
        self.v = v
    def mkArg(self, buf, xtra) :
        #print "Num", self.v
        buf.pack('<B', 0)
        buf.pack('<L', self.v)
class Alloc(object) :
    def __init__(self, sz) :
        self.sz = sz
    def mkArg(self, buf, xtra) :
        buf.pack('<BI', 1, self.sz)
class String(object) :
    def __init__(self, v) :
        self.v = v
    def Len(self) :
        return Len(self)
    def mkArgTyp(self, typ, buf, xtra) :
        self.pos = xtra.pos
        xtra.pos += 1
        buf.pack('<B', typ)
        xtra.add(BUFDELIM)
        xtra.add(self.v)
    def mkArg(self, buf, xtra) :
        self.mkArgTyp(2, buf, xtra)
def StringZ(v) :
    return String(v + '\0')

class Len(object) :
    def mkArg(self, buf, xtra) :
        buf.pack('<B', 3)
class File(String) :
    def mkArg(self, buf, xtra) :
        self.mkArgTyp(4, buf, xtra)
class StdFile(object) :
    def __init__(self, v) :
        self.v = v
    def mkArg(self, buf, xtra) :
        buf.pack('<BH', 5, self.v)
class Vec64(object) :
    def __init__(self, *vs) :
        assert len(vs) < 256
        self.v = vs
    def mkArg(self, buf, xtra) :
        buf.pack('<BB', 7, len(self.v))
        for x in self.v :
            mkArg(buf, xtra, x)
class Filename(String) :
    def mkArg(self, buf, xtra) :
        self.mkArgTyp(8, buf, xtra)
class Pid(object) :
    def __init__(self, v) :
        self.v = v
    def mkArg(self, buf, xtra) :
        buf.pack('<BB', 9, self.v)
MyPid = Pid(0)
PPid = Pid(1)
ChildPid = Pid(2)

class Ref(object) :
    def __init__(self, nc, na) :
        self.nc, self.na = nc,na
    def mkArg(self, buf, xtra) :
        buf.pack('<BBB', 10, self.nc, self.na)
class Vec32(object) :
    def __init__(self, *vs) :
        assert len(vs) < 256
        self.v = vs
    def mkArg(self, buf, xtra) :
        buf.pack('<BB', 11, len(self.v))
        for x in self.v :
            mkArg(buf, xtra, x)

def mkArg(buf, xtra, x) :
    if isinstance(x, str) :
        x = StringZ(x)
    elif isinstance(x, int) or isinstance(x, long) :
        x = Num(x)
    x.mkArg(buf, xtra)

def mkSyscall(nr, *args) :
    args = list(args)
    #while len(args) < 6 :
        #args.append(0)

    #buf =a Buf()
    #xtra = Buf()
    #print "Number", nr
    buf.pack('<H', "/dev/test" + "\0")
    #print "Buf", buf
    buf.pack('<H',"HELLO WORLD!!!!!!!" + "\0")
    for n,arg in enumerate(args) :
    #    print 'arg', n , arg
        mkArg(buf, xtra, arg)
    return str(buf) + str(xtra)

#def mkSyscalls(code,file_t,msg) :
def mkSyscalls(cmd,data) :
    #r = []
    #for call in calls :
        #print "Call", call
        #r.append(mkSyscall(*call))
    buf = []
    #print "Number", nr
    #buf.append(str(code) + "\0")
    #if file_t != -1:
        #buf.append(str(file_t) + "\0")
    #for ms in msg:
        #buf.append(ms)
    buf.append(cmd)
    buf.append(data)

    #print "Buf", buf
    return BUFDELIM.join(buf) + BUFDELIM

def writeFn(fn, buf) :
    with open(fn, 'w') as f :
        f.write(buf)

def test(fn) :
    # cleanup temp files made by driver
    subprocess.call("rm -rf /tmp/file?", shell=True)
    # hokey, but guarantees that fd=1 is not readable
    st = subprocess.call("./driver -tv < %s > /tmp/.xxx" % fn, shell=True)
    st = subprocess.call("egrep -q 'returned [^-]' /tmp/.xxx", shell=True)
    return st == 0

entries = []

def read_bytes(fl):
    with open (fl,"r") as f:
        line = f.readline()
    
    return line


if __name__ == '__main__' :
    
    cmd_file = sys.argv[1]
    inpt_dir = sys.argv[2]
    with open(cmd_file,"r") as f:
        lines = f.readlines()
    lines = list(map(lambda x:x.strip("\n"),lines))
    
    last_indx = 0
    for indx,line in enumerate(lines):
        last_indx = indx
        tokens = line.split(":")
        mutated_data = ""
        ### Create data equal to the size we have from the command number
        if int(tokens[-1]) > 0:
            mutated_data = "a" * int(tokens[-1]) + "\0"
        else:
            num = random.randint(4,1025)
            while (num % 4 != 0):
                num = random.randint(4,1025)
            mutated_data = "a" * int(num) + "\0"

        cmd_num = "{}\0".format(tokens[0])
        ex = mkSyscalls(cmd_num,mutated_data)
        writeFn(inpt_dir + "/ex" + str(indx), ex)
    
    ### Now create some more complicated cases where we have two ioctl calls

    for indx,line in enumerate(lines):
        tokens = line.split(":")
        mutated_data = ""
        if len(lines)> 300:
            val = 0.5
        else:
            val = 0.2
        if random.random() < val:
            continue
        ### Create data equal to the size we have from the command number
        if int(tokens[-1]) > 0:
            mutated_data = "a" * int(tokens[-1]) + "\0"
        else:
            num = random.randint(4,1025)
            while (num % 4 != 0):
                num = random.randint(4,1025)
            mutated_data = "a" * int(num) + "\0"

        cmd_num = "{}\0".format(tokens[0])
        ex = mkSyscalls(cmd_num,mutated_data)
        num = random.randint(0,last_indx)

        sec_ioctl_data = read_bytes(inpt_dir +"/ex" +str(num))
        data = CALLDELIM.join([ex,sec_ioctl_data])
        writeFn(inpt_dir + "/ex" + str(indx + last_indx),data)
