CC      = gcc
INCLUDE = -I../openssl
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
         tcm_test

all: $(TARGET)

tcm_write: $(OBJECTS_WRITE)
	$(CC) -o tcm_write $(OBJECTS_WRITE) $(INCLUDE) $(CFLAGS) $(LIB)

tcm_test: $(OBJECTS_TEST)
	$(CC) -o tcm_test $(OBJECTS_TEST) $(INCLUDE) $(CFLAGS) $(LIB)

.c.o:
	$(CC) $(INCLUDE) $(CFLAGS) -c -o $@ $<

.PHONY:clean
clean:
	rm -rf *.o $(TARGET)
