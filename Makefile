all:
	cd ./tcmalg; make -j8
	cd ./tcm-c; make -j8

.PHONY:clean
clean:
	cd ./tcmalg; make clean
	cd ./tcm-c; make clean
