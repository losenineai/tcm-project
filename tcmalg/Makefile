CC      = gcc
AR      = ar
FLAGS   = -fPIC -D_REENTRANT
CFLAGS  = -g -O2 -Werror -fno-strict-aliasing -shared -fPIC
INCLUDE = -I../openssl

TCMALG_SO = libtcmalg.so
TCMALG_LIB = libtcmalg.a

OBJECTS = bn_add.o \
		bn_asm.o \
		bn_ctx.o \
		bn_div.o \
		bnEx.o \
		bn_exp.o \
		bn_gcd.o \
		bn_kron.o \
		bn_lib.o \
		bn_mod.o \
		bn_mont.o \
		bn_mul.o \
		bn_print.o \
		bn_recp.o \
		bn_shift.o \
		bn_sqr.o \
		bn_sqrt.o \
		bn_word.o \
		calculate_hash.o \
		ec_decrypt.o \
		ec_encrypt.o \
		ec_genkey.o \
		ec_init.o \
		ec_operations.o \
		ec_signature.o \
		ec_verify.o \
		mem.o \
		sch.o \
		SMS4.o \
		tcm_ecc.o \
		tcm_ecc_exchange.o \
		tcm_hash.o \
		tcm_rand.o \
		tcm_sms4.o \
		tcm_bn.o \
		seal.o

all: $(TCMALG_SO) $(TCMALG_LIB)

$(TCMALG_SO): $(OBJECTS)
	$(CC) ${OBJECTS} ${FLAGS} ${INCLUDE} -shared -o ${TCMALG_SO} ${LIB}
	cp $(TCMALG_SO) /usr/lib

$(TCMALG_LIB): $(OBJECTS)
	$(AR) -r $@ $^

.c.o:
	$(CC) $(INCLUDE) $(CFLAGS) -c -o $@ $<

seal.o: seal.c
	$(CC) -c seal.c -fPIC -fno-builtin $(INCLUDE)

.PHONY: clean
clean:
	rm -f *.o $(TCMALG_SO) $(TCMALG_LIB)
	rm -f /usr/lib/$(TCMALG_SO)
