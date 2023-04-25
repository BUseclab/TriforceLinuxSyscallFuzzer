#!/bin/bash
#


cd ./arm_new
make clean
make
cd ../arm_old
make clean
make
cd ../mips_old/le
make clean
make
cd ../../mips_old/be
make clean
make
cd ../mips_new/le
make clean
make
cd ../../mips_new/be
make clean
make
