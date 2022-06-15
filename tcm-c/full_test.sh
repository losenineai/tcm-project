#!/bin/bash

./tcm_test /s1
./tcm_test /f
./tcm_test /s0
./tcm_test /vp qwertyuiop
./tcm_test /cp qwertyuiop asdfghjkl
# ./tcm_test /vp asdfghjkl
./tcm_test /cp asdfghjkl qwertyuiop

./tcm_test /sm2s1
./tcm_test /nvw goon.bin
./tcm_test /nvr
./tcm_test /sm4t0 Makefile Makefileee
./tcm_test /sm4t1 Makefileee Makefile1
md5sum Makefile Makefile1
