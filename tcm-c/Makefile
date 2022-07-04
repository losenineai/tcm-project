CC      = gcc
INCLUDE = -I../openssl
LIBS    = ../tcmalg/libtcmalg.a
LIB     = -ltcmalg
CFLAGS  = $(FLAGS_GLOBAL)
CFLAGS  += -g -Werror -fno-strict-aliasing

OBJECTS = common.o \
          ftdi_spi_tpm.o \
          tcm_hash.o \
          tcm_ecc.o \
          tpcm_func.o \
          tpcm_util.o

OBJECTS_TEST  = $(OBJECTS) tcm_test.o
OBJECTS_WRITE = $(OBJECTS) tcm_write.o

TARGET = tcm_write \
         tcm_test \
         tcm_write1 \
         tcm_test1

all: $(TARGET)

#使用动态库
tcm_write: $(OBJECTS_WRITE)
	$(CC) -o tcm_write $(OBJECTS_WRITE) $(INCLUDE) $(CFLAGS) $(LIB)

tcm_test: $(OBJECTS_TEST)
	$(CC) -o tcm_test $(OBJECTS_TEST) $(INCLUDE) $(CFLAGS) $(LIB)

#使用静态库
tcm_write1: $(OBJECTS_WRITE)
	$(CC) -o tcm_write1 $(OBJECTS_WRITE) $(INCLUDE) $(CFLAGS) $(LIBS)

tcm_test1: $(OBJECTS_TEST)
	$(CC) -o tcm_test1 $(OBJECTS_TEST) $(INCLUDE) $(CFLAGS) $(LIBS)

.c.o:
	$(CC) $(INCLUDE) $(CFLAGS) -c -o $@ $<

.PHONY:clean
clean:
	rm -rf *.o $(TARGET)
