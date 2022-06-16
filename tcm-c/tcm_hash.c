/******************************************
File    :tcm_hash.c  
Author  :linyang
Date    :11/21/2006
******************************************/
#include <stdlib.h>

#include "ec_operations.h"
#include "tcm_hash.h"

static void sch_starts(sch_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;
}

static void sch_process(sch_context *ctx, uint8_t data[64])
{
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1,SS2,TT1,TT2;
    uint32_t j,T,FF,GG;

    GET_UINT32( W[0],  data,  0 );
    GET_UINT32( W[1],  data,  4 );
    GET_UINT32( W[2],  data,  8 );
    GET_UINT32( W[3],  data, 12 );
    GET_UINT32( W[4],  data, 16 );
    GET_UINT32( W[5],  data, 20 );
    GET_UINT32( W[6],  data, 24 );
    GET_UINT32( W[7],  data, 28 );
    GET_UINT32( W[8],  data, 32 );
    GET_UINT32( W[9],  data, 36 );
    GET_UINT32( W[10], data, 40 );
    GET_UINT32( W[11], data, 44 );
    GET_UINT32( W[12], data, 48 );
    GET_UINT32( W[13], data, 52 );
    GET_UINT32( W[14], data, 56 );
    GET_UINT32( W[15], data, 60 );

    for (j=16;j<68;j++)
    {
        // W[j] = P1( (W[j-16]^W[j-9]^ROTL(W[j-3],15)) ) ^ (ROTL(W[j-13],7)) ^ W[j-6]; 
        //上面代码会在release版本出错 linyang 2006.12.11
        uint32_t temp;
        temp = W[j-16]^W[j-9]^ROTL(W[j-3],15);
        W[j] = P1( temp ) ^ (ROTL(W[j-13],7)) ^ W[j-6];
    }
    for (j=0;j<64;j++)
    {
        W1[j] = W[j] ^ W[j+4];
    }
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    for (j=0;j<64;j++)
    {
        T = (j<16)?(0x79CC4519):(0x7A879D8A);
        SS1 =  ROTL(ROTL(A,12) + E + ROTL(T,j), 7);
        SS2 = SS1 ^ ROTL(A,12);
        FF = (j<16)?(A^B^C):((A&B)|(A&C)|(B&C));
        GG = (j<16)?(E^F^G):((E&F)|((~E)&G));
        TT1 = FF + D + SS2 + W1[j];
        TT2 = GG + H + SS1 + W[j];
        D = C;
        C = ROTL(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F,19);
        F = E;
        E = P0(TT2);
    }

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

static void sch_update(sch_context *ctx, uint8_t *input, uint32_t length)
{
    uint32_t left, fill;

    if( !length )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < length )
        ctx->total[1]++;

    if( left && length >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        sch_process( ctx, ctx->buffer );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while(length >= 64)
    {
        sch_process(ctx, input);
        length -= 64;
        input  += 64;
    }

    if(length)
    {
        memcpy((void *)(ctx->buffer + left), (void *)input, length);
    }
}

static void sch_finish(sch_context *ctx, uint8_t diglen, uint8_t digest[32])
{
    uint32_t last, padn;
    uint32_t high, low;
    uint8_t msglen[8];
    uint32_t y1[6],y2[5]; 

    high = (ctx->total[0] >> 29) | (ctx->total[1] <<  3);
    low  = (ctx->total[0] <<  3);

    PUT_UINT32(high, msglen, 0);
    PUT_UINT32(low,  msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sch_update( ctx, sch_padding, padn );
    sch_update( ctx, msglen, 8 );

    // if( diglen==256)
    if( diglen==32)
    {
        PUT_UINT32( ctx->state[0], digest,  0 );
        PUT_UINT32( ctx->state[1], digest,  4 );
        PUT_UINT32( ctx->state[2], digest,  8 );
        PUT_UINT32( ctx->state[3], digest, 12 );
        PUT_UINT32( ctx->state[4], digest, 16 );
        PUT_UINT32( ctx->state[5], digest, 20 );
        PUT_UINT32( ctx->state[6], digest, 24 );
        PUT_UINT32( ctx->state[7], digest, 28 );
    }
   // else if( diglen==192)
    else if( diglen==24)
    {
        y1[0] = ctx->state[0] ^ ctx->state[1] ^ ctx->state[4];
        y1[1] = ctx->state[1] ^ ctx->state[5];
        y1[2] = ctx->state[2] ^ ctx->state[6];
        y1[3] = ctx->state[3] ^ ctx->state[7];
        y1[4] = ctx->state[5] ^ ctx->state[2];
        y1[5] = ctx->state[3] ^ ctx->state[6];
        PUT_UINT32( y1[0], digest,  0 );
        PUT_UINT32( y1[1], digest,  4 );
        PUT_UINT32( y1[2], digest,  8 );
        PUT_UINT32( y1[3], digest, 12 );
        PUT_UINT32( y1[4], digest, 16 );
        PUT_UINT32( y1[5], digest, 20 );
    }
    // else if( diglen==160)
    else if( diglen==20)
    {
        y2[0] = ctx->state[0] ^ ctx->state[1] ^ ctx->state[4];
        y2[1] = ctx->state[1] ^ ctx->state[5] ^ ctx->state[2];
        y2[2] = ctx->state[2] ^ ctx->state[6];
        y2[3] = ctx->state[3] ^ ctx->state[7];
        y2[4] = ctx->state[3] ^ ctx->state[6];
        PUT_UINT32( y2[0], digest,  0 );
        PUT_UINT32( y2[1], digest,  4 );
        PUT_UINT32( y2[2], digest,  8 );
        PUT_UINT32( y2[3], digest, 12 );
        PUT_UINT32( y2[4], digest, 16 );
    }
}

void tcm_sch_starts(sch_context *ctx)
{
    sch_starts(ctx);
}

void tcm_sch_update(sch_context *ctx, uint8_t *input, uint32_t length)
{
    sch_update(ctx, input, length);
}

void tcm_sch_finish(sch_context *ctx, uint8_t digest[32])
{
    sch_finish(ctx, 32, digest);
}

int tcm_sch_256(unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[32])
{
    sch_context ctx;
    unsigned char sch256[32];

    sch_starts(&ctx);
    sch_update(&ctx, (uint8_t *)pdata_in, datalen_in);
    sch_finish(&ctx, sizeof(sch256), sch256);

    memcpy(digest, sch256, sizeof(sch256));

    return 0;
}

int tcm_sch_192( unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[24])
{
    sch_context ctx;
    unsigned char sch192[24];

    sch_starts(&ctx);
    sch_update(&ctx, (uint8_t *)pdata_in, datalen_in);
    sch_finish(&ctx, sizeof(sch192), sch192);

    memcpy(digest, sch192, sizeof(sch192));

    return 0;
}

int tcm_sch_160( unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[20])
{
    sch_context ctx;
    unsigned char sch160[20];

    sch_starts(&ctx);
    sch_update(&ctx, (uint8_t *)pdata_in, datalen_in);
    sch_finish(&ctx, sizeof(sch160), sch160);

    memcpy(digest, sch160, sizeof(sch160));

    return 0;
}

//使用256bit的hash
int tcm_sch_hash(unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[32])
{
    return tcm_sch_256(datalen_in, pdata_in, digest);
}

int tcm_kdf(/*out*/uint8_t *mask, /*in*/int klen, /*in*/uint8_t *z, /*in*/ int zlen)
{
    int ct;
    uint8_t T[hLen];
    int k;
    uint8_t *seed;

    seed = (uint8_t *)malloc(zlen+4);
    if( seed == 0 )
    {
        return 1;
    }
    memset(seed, 0, zlen+4);
    memcpy(seed, z, zlen);

    for(ct=0;ct<(klen/hLen);ct++)
    {
        seed[zlen]=(uint8_t )((ct+1)>>24);
        seed[zlen+1]=(uint8_t )((ct+1)>>16);
        seed[zlen+2]=(uint8_t )((ct+1)>>8);
        seed[zlen+3]=(uint8_t )(ct+1);
        tcm_sch_256(zlen+4, seed, &mask[ct*32]);
    }

    if(klen%hLen !=0)
    {
        seed[zlen]=(uint8_t )((ct+1)>>24);
        seed[zlen+1]=(uint8_t )((ct+1)>>16);
        seed[zlen+2]=(uint8_t )((ct+1)>>8);
        seed[zlen+3]=(uint8_t )(ct+1);
        tcm_sch_256(zlen+4, seed, T);

        for(ct=ct*hLen,k=0;ct<klen;ct++,k++)
            mask[ct]=T[k];
    }

    free(seed);
    return 0;
}

/****************************************************************************************************
输入:unsigned char  *text;                //pointer to data stream 
输入:unsigned int   text_len;             //length of data stream 
输入:unsigned char  *key;                 //pointer to authentication key 
输入:unsigned int   key_len;              //length of authentication key 
输入:unsigned int   digest_len;           //length of digest
输出:unsigned char  *digest;              //caller digest to be filled in 

目前支持最大的key长度为256八位组
目前支持摘要最大长度为32八位组

返回值:正确返回0,错误返回1
*****************************************************************************************************/
int tcm_hmac(unsigned char *text, unsigned int text_len,
             unsigned char *key, unsigned int key_len,
             unsigned char digest[32])
{
    sch_context context;

    unsigned char k_ipad[65];    /* inner padding key XORd with ipad */
    unsigned char k_opad[65];    /* outer padding key XORd with opad */
    unsigned char tk[32];
    unsigned char tempdigest[32];
    unsigned char tempkey[256];
    int i;

    memcpy(tempkey,key,key_len);

    /* if key is longer than 64 bytes reset it to key=sch256(key) */
    if (key_len > 64)
    {
        sch_context tctx;           

        sch_starts(&tctx);
        sch_update(&tctx,(uint8_t *)tempkey,key_len);
        sch_finish(&tctx, 32, tk);              

        memcpy(tempkey,tk,32);
        key_len = 32;
    }

    /*
    * the HMAC_sch transform looks like:
    *
    * sch(K XOR opad, sch256(K XOR ipad, text))
    *
    * where K is an n byte key
    * ipad is the byte 0x36 repeated 64 times
    * opad is the byte 0x5c repeated 64 times
    * and text is the data being protected
    */

    /* start out by storing key in pads */
    memset( k_ipad, 0, sizeof(k_ipad));
    memset( k_opad, 0, sizeof(k_opad));
    memcpy( k_ipad, tempkey, key_len);
    memcpy( k_opad, tempkey, key_len);

    /* XOR key with ipad and opad values */
    for (i=0; i<64; i++)
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /* perform inner sch256 */
    sch_starts(&context);
    /* init context for 1st pass */
    sch_update(&context,(uint8_t *)k_ipad, 64);
    sch_update(&context,(uint8_t *)text,text_len);
    sch_finish(&context, 32, tempdigest);

    /* perform outer sch256 */       
    sch_starts(&context);
    /* init context for 2nd pass */
    sch_update(&context,(uint8_t *)k_opad,64);
    sch_update(&context,(uint8_t *)tempdigest,32);
    sch_finish(&context, 32, tempdigest);
    /* finish up 2nd pass */

    memcpy(digest, tempdigest, 32);
    return 0;
}

//采用软件实现的sm3哈希算法
int TCM_SM3_soft(BYTE* content, size_t length, BYTE digest[32])
{
    BYTE sm3_data[MAX_BUFSIZE]={0x00};
#if 0
    unsigned int len = 0;
    StringToHex(content, sm3_data, &len);
    length = len;
#else
    memcpy(sm3_data, content, length);
#endif
    // tcmPrintf("sm3 data", length, sm3_data);

    tcm_sch_hash(length, sm3_data, digest);
    // tcmPrintf("SM3_soft result", 32, digest);

    return 0;
}
