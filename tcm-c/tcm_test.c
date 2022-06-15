#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tcm_hash.h"
#include "common.h"
#include "tpcm_func.h"
#include "ftdi_spi_tpm.h"
#include "tcm_ecc.h"
#include "tpcm_util.h"

extern int g_iDisplayFlag;   //=0,display,    =1,not dispaly

#if 0
// 龙芯 SPI参数
// 经过示波器测试，SPI总线频率设为5MHZ时，波形为较好的方波，频率设置越高，方波锯齿化越严重
#define SPI_BUS_FREQ     5000000
#define SPI_DEV1_NAME    "/dev/spidev32766.1"
#else
// orangepi SPI参数
// orangepi官方文档中显示SPI总线频率为65MHZ
#define SPI_BUS_FREQ     10000000
#define SPI_DEV1_NAME    "/dev/spidev1.1"
#endif

static int piece_data(BYTE data[256], int length, char* title)
{
    char buffer[1024]={0};
    char tmp[8];
    int i;

    for (i=0;i<length;i++)
    {
        sprintf(tmp, "0x%02x,", data[i]);
        strcat(buffer, tmp);
    }
    printf("%s=\n%s\n", title, buffer);
}

int sm2_signed_verify(BYTE hash[32], BYTE pubkey[65], BYTE signed_data[64])
{
    int ret=0;
    /* 调用验签函数前需要调用该初始化函数，调用完成后需要调用释放函数 */
    tcm_ecc_init();

    ret = tcm_ecc_verify(hash, 32, signed_data, 64, pubkey, 65);
    tcm_ecc_release();

    if (ret == 0)
        printf("\ntcm ecc sm2 verify success\n\n");
    else
        printf("\ntcm ecc sm2 verify failed\n\n");

    return ret;
}

static int sm2_signed(void)
{
    int ret=0;
    BYTE ownerAuth[32] = {0x00};  //授权值的sm3哈希值
    ownerAuthInit(OWNER_PASSWD, ownerAuth);

    BYTE hash[32]={0xfe,0xb9,0xc7,0xde,0xd4,0x30,0xcc,0x5d, 0xb0,0x29,0x25,0x51,0xf6,0xbb,0x4e,0xbe,
                   0xc7,0xde,0xd4,0x30,0xcc,0x5d,0xb0,0x29, 0x3e,0xb9,0xc7,0xde,0xd4,0x30,0x25,0x51};
    BYTE signed_data[64]={0x00};
    BYTE pubkey[65]={0x00};
    BYTE sm2_key[69]={0x00};
    BYTE key_handle[4]={0x00};
    BYTE offset[4]={0x00};

    ret = TCM_read_sm2_keyhandle_nv(ownerAuth, offset, sm2_key);
    if (ret)
        return ret;

    tcmPrintf("sm2 key", 69, sm2_key);
    memcpy(key_handle, sm2_key, 4);
    memcpy(pubkey, sm2_key+4, 65);

    ret = TCM_Sign(key_handle, hash, signed_data);
    if (ret == 12)
    {
        //设备断电过，以前加载的密钥已失效，返回12，密钥句柄不能被解读，应该重新建立sm2密钥对
        ret = TCM_Sign_full(ownerAuth, hash, signed_data, pubkey);
        if (ret)
            return ret;

        sm2_signed_verify(hash, pubkey, signed_data);
        piece_data(hash, 32, "hash");
        piece_data(pubkey, 65, "pub key");
        piece_data(signed_data, 64, "signed data");
    }
    else if (ret == 0)
    {
        sm2_signed_verify(hash, pubkey, signed_data);
        piece_data(hash, 32, "hash");
        piece_data(pubkey, 65, "pub key");
        piece_data(signed_data, 64, "signed data");
    }

    FtdiStop();
    return ret;
}

static int sm2_verify_signed(void)
{
    int ret=0;
    /* 调用验签函数前需要调用该初始化函数，调用完成后需要调用释放函数 */
    tcm_ecc_init();

    BYTE hash[32]={0xfe,0xb9,0xc7,0xde,0xd4,0x30,0xcc,0x5d,0xb0,0x29,0x25,0x51,0xf6,0xbb,0x4e,0xbe,0xc7,0xde,0xd4,0x30,0xcc,0x5d,0xb0,0x29,
        0x3e,0xb9,0xc7,0xde,0xd4,0x30,0x25,0x51};
    BYTE pubkey[65]={0x04,0xac,0xe1,0x63,0xd4,0xea,0xc0,0x7d,0x35,0xb9,0x00,0x04,0xf6,0xa2,0x67,0xf3,0x28,0x96,0x88,0x90,0x8a,0xa2,0xe6,0x10,
        0xae,0x43,0x27,0x93,0x0f,0xf1,0xea,0x6f,0xde,0x7c,0x60,0xce,0xee,0x61,0x73,0xdc,0xaf,0x4c,0x44,0x5e,0x7d,0xa6,0x5f,0xd8,0x16,0x06,
        0x0f,0x31,0xf7,0x61,0x8d,0x94,0xb3,0x34,0x76,0xea,0x6b,0x6c,0x63,0xf0,0x96};
    BYTE signed_data[64]={0x13,0xaa,0x2b,0x72,0x25,0x78,0x44,0xfe,0xdf,0xc5,0x9f,0xf4,0x4a,0x2b,0x95,0xa9,0x37,0x9a,0xd3,0xb1,0x52,0x49,0xcd,
        0xfa,0x3c,0xe0,0x1d,0xc6,0x50,0xca,0x7f,0xc6,0xbc,0x04,0xcf,0xe2,0x6d,0xf7,0xf0,0x4c,0x0f,0x7b,0x9c,0x99,0x7b,0xa6,0x0c,0x4a,0xd4,
        0x1f,0xef,0x73,0xe1,0xd4,0xb8,0xe5,0x50,0x03,0xfe,0xea,0x0c,0x00,0x31,0x76};

    ret = tcm_ecc_verify(hash, 32, signed_data, 64, pubkey, 65);
    tcm_ecc_release();

    if (ret == 0)
        printf("\ntcm ecc sm2 verify success\n\n");
    else
        printf("\ntcm ecc sm2 verify failed\n\n");

    return ret;
}

static int sm4_encrypt_file(char* input_file, char* output_file)
{
    int ret=0;
    BYTE handle[4]={0x00};
    BYTE ownerAuth[32] = {0x00};
    ownerAuthInit(OWNER_PASSWD, ownerAuth);
    BYTE key[16]={0xd4,0x30,0xcc,0x5d,0xb0,0x29,0x25,0x51, 0x3e,0xb9,0xc7,0xde,0xf6,0xbb,0x4e,0xbe};
    BYTE IV[16] ={0x3e,0xb9,0xc7,0xde,0xd4,0x31,0xcc,0x5d, 0xc7,0xde,0xd4,0x30,0xcc,0x5d,0xb0,0x2a};
    BYTE offset[4]={0x00,0x00,0x00,0x00};
    BYTE sm4_key[20]={0x00};

    ret = TCM_read_sm4_keyhandle_nv(ownerAuth, offset, sm4_key);
    if (ret)
        return ret;

    tcmPrintf("sm4_key", 20, sm4_key);
    memcpy(handle, sm4_key, 4);

    BYTE data[MAX_BUFSIZE]={0x00};
    uint32_t length=0;
    BYTE enc_data[MAX_BUFSIZE]={0x00};
    uint32_t enc_data_len=0;

    ret = read_File_data(input_file, data, &length);
    ret = TCM_SM4Encrypt(handle, IV, data, length, enc_data, &enc_data_len);
    if (ret == 12)
    {
        ret = write_sm4_key(ownerAuth, key);
        if (ret)
            return ret;

        ret = TCM_read_sm4_keyhandle_nv(ownerAuth, offset, sm4_key);
        if (ret)
            return ret;

        tcmPrintf("sm4_key", 20, sm4_key);
        memcpy(handle, sm4_key, 4);

        ret = TCM_SM4Encrypt(handle, IV, data, length, enc_data, &enc_data_len);
        if (ret == 0)
        {
            ret = write_File_data(output_file, enc_data, enc_data_len);
        }
        else
        {
            FtdiStop();
            return ret;
        }
    }
    else if (ret == 0)
    {
        ret = write_File_data(output_file, enc_data, enc_data_len);
    }

    FtdiStop();
    return ret;
}

static int sm4_decrypt_file(char* input_file, char* output_file)
{
    int ret=0;
    BYTE handle[4]={0x00};
    BYTE ownerAuth[32] = {0x00};
    ownerAuthInit(OWNER_PASSWD, ownerAuth);
    BYTE key[16]={0xd4,0x30,0xcc,0x5d,0xb0,0x29,0x25,0x51, 0x3e,0xb9,0xc7,0xde,0xf6,0xbb,0x4e,0xbe};
    BYTE IV[16] ={0x3e,0xb9,0xc7,0xde,0xd4,0x31,0xcc,0x5d, 0xc7,0xde,0xd4,0x30,0xcc,0x5d,0xb0,0x2a};
    BYTE offset[4]={0x00,0x00,0x00,0x00};
    BYTE sm4_key[20]={0x00};

    ret = TCM_read_sm4_keyhandle_nv(ownerAuth, offset, sm4_key);
    if (ret)
        return ret;

    tcmPrintf("sm4_key", 20, sm4_key);
    memcpy(handle, sm4_key, 4);

    BYTE data[MAX_BUFSIZE]={0x00};
    uint32_t length=0;
    BYTE enc_data[MAX_BUFSIZE]={0x00};
    uint32_t enc_data_len=0;

    ret = read_File_data(input_file, enc_data, &enc_data_len);
    ret = TCM_SM4Decrypt(handle, IV, enc_data, enc_data_len, data, &length);
    if (ret == 12)
    {
        ret = write_sm4_key(ownerAuth, key);
        if (ret)
            return ret;

        ret = TCM_read_sm4_keyhandle_nv(ownerAuth, offset, sm4_key);
        if (ret)
            return ret;

        tcmPrintf("sm4_key", 20, sm4_key);
        memcpy(handle, sm4_key, 4);

        ret = TCM_SM4Decrypt(handle, IV, enc_data, enc_data_len, data, &length);
        if (ret == 0)
        {
            ret = write_File_data(output_file, data, length);
        }
        else
        {
            FtdiStop();
            return ret;
        }
    }
    else if (ret == 0)
    {
        ret = write_File_data(output_file, data, length);
    }

    FtdiStop();
    return ret;
}

static int sm4_en_decrypt(void)
{
    int ret = 0;
    BYTE ownerAuth[32] = {0x00};  //授权值的sm3哈希值
    ownerAuthInit(OWNER_PASSWD, ownerAuth);

    /* 待加密数据 */
    BYTE data[MAX_BUFSIZE]={0xfe,0xb9,0xc7,0xde,0xd4,0x30,0xcc,0x5d, 0xb0,0x29,0x25,0x51,0xf6,0xbb,0x4e,0xbe,
                   0xc7,0xde,0xd4,0x30,0xcc,0x5d,0xb0,0x29, 0x3e,0xb9,0xc7,0xde,0xd4,0x30,0x25,0x51,
                   0x5a,0x60,0x33,0x44};

    /* sm4 key */
    BYTE key[16]={0xd4,0x30,0xcc,0x5d,0xb0,0x29,0x25,0x51, 0x3e,0xb9,0xc7,0xde,0xf6,0xbb,0x4e,0xbe};
    /* CBC模式下使用的IV，加解密需要使用同样的密钥和IV */
    BYTE IV[16]={0x3e,0xb9,0xc7,0xde,0xd4,0x31,0xcc,0x5d, 0xc7,0xde,0xd4,0x30,0xcc,0x5d,0xb0,0x2a};
    BYTE enc_data[MAX_BUFSIZE]={0x00};
    uint32_t enc_data_len=0;
    BYTE keyinfo[159]={0x00};
    BYTE handle[4]={0x00};
    BYTE offset[4]={0x00,0x00,0x00,0x00};
    BYTE sm4_key[20]={0x00};

    ret = TCM_read_sm4_keyhandle_nv(ownerAuth, offset, sm4_key);
    if (ret)
        return ret;

    tcmPrintf("sm4_key", 20, sm4_key);
    memcpy(handle, sm4_key, 4);

    ret = TCM_SM4Encrypt(handle, IV, data, 36, enc_data, &enc_data_len);
    if (ret == 12)
    {
        ret = TCM_WrapKey(ownerAuth, key, keyinfo);
        if (ret == 0)
        {
            ret = TCM_LoadKey(ownerAuth, keyinfo, 159, handle);
            tcmPrintf("handle", 4, handle);

            memcpy(sm4_key, handle, 4);
            memcpy(sm4_key+4, key, 16);
            ret = TCM_write_sm4_keyhandle_nv(ownerAuth, offset, sm4_key);
            if (ret)
                return ret;

            ret = TCM_SM4Encrypt(handle, IV, data, 36, enc_data, &enc_data_len);
            if (ret == 0)
            {
                BYTE data1[MAX_BUFSIZE]={0x00};
                uint32_t data_len=0;
                tcmPrintf("enc_data", enc_data_len, enc_data);

                ret = TCM_SM4Decrypt(handle, IV, enc_data, enc_data_len, data1, &data_len);
                if (ret == 0)
                {
                    tcmPrintf("data1", data_len, data1);
                }
            } else {
                printf("TCM_SM4Encrypt failed\n");
            }
        } else {
            printf("TCM_WrapKey failed\n");
        }
    }
    else if (ret == 0)
    {
        BYTE data1[MAX_BUFSIZE]={0x00};
        uint32_t data_len=0;
        tcmPrintf("enc_data", enc_data_len, enc_data);

        ret = TCM_SM4Decrypt(handle, IV, enc_data, enc_data_len, data1, &data_len);
        if (ret == 0)
        {
            tcmPrintf("data", data_len, data1);
        } else {
            printf("TCM_SM4Decrypt failed\n");
        }
    }

    FtdiStop();
    return ret;
}

static int create_load_key(void)
{
    int ret=0;
    BYTE ownerAuth[32] = {0x00};  //授权值的sm3哈希值
    ownerAuthInit(OWNER_PASSWD, ownerAuth);
    
    BYTE key_out[248]={0x00};
    BYTE pubkey[65]={0x00};

    ret = TCM_CreateWrapKey(ownerAuth, key_out, pubkey);
    if (0 == ret)
    {
        printf("tcm_createwrapkey Success\n");
        tcmPrintf("pubkey", 65, pubkey);
        // tcmPrintf("created key out", 248, key_out);
        BYTE key_handle[4];
        BYTE pubkey1[128];

        TCM_LoadKey(ownerAuth, key_out, 248, key_handle);

        // TCM_GetPubKey(ownerAuth, key_handle, pubkey1);
        // printf("+++++++++++++++++++++++++++++++++\n");
        // tcmPrintf("key_handle", 4, key_handle);
        piece_data(key_handle, 4, "key_handle");
    }
    else
    {
        printf("tcm_createwrapkey Failed\n");
    }

    return ret;
}

static int certify_key_test()
{
    int ret=0;
    BYTE ownerAuth[32] = {0x00};  //授权值的sm3哈希值
    ownerAuthInit(OWNER_PASSWD, ownerAuth);
    BYTE key_out[248]={0x00};
    BYTE pubkey[65]={0x00};
    BYTE key_handle1[4];
    BYTE key_handle2[4];

    ret = TCM_CreateWrapKey(ownerAuth, key_out, pubkey);
    if (0 == ret)
    {
        TCM_LoadKey(ownerAuth, key_out, 248, key_handle1);
    }
    else
    {
        printf("tcm_createwrapkey Failed\n");
        return 1;
    }

    ret = TCM_CreateWrapKey(ownerAuth, key_out, pubkey);
    if (0 == ret)
    {
        TCM_LoadKey(ownerAuth, key_out, 248, key_handle2);
    }
    else
    {
        printf("tcm_createwrapkey Failed\n");
        return 1;
    }

    ret = TCM_CertifyKey(key_handle1, key_handle2);

    return ret;
}

int pcrextend_test()
{
    int ret=0;
    BYTE index[4]={0x00,0x00,0x00,0x08};
    BYTE digest[32]={0xfe,0xb9,0xc7,0xde,0xd4,0x30,0xcc,0x5d,
        0xb0,0x29,0x25,0x51,0xf6,0xbb,0x4e,0xbe,
        0xc7,0xde,0xd4,0x30,0xcc,0x5d,0xb0,0x29,
        0x3e,0xb9,0xc7,0xde,0xd4,0x30,0x25,0x51};
    BYTE PCR_data[32];
    BYTE data[64];
    BYTE sm3_hash[32];

    // printf("%s, %d\n", __func__, __LINE__);
    ret = TCM_PCRRead(index, PCR_data);
    tcmPrintf("pcr data", 32, PCR_data);

    //两种方法均可正确执行
#if 1
    memcpy(data, PCR_data, 32);
    memcpy(data+32, digest, 32);
#else
    memcpy(data, digest, 32);
    memcpy(data+32, PCR_data, 32);
#endif
    TCM_SM3_soft(data, 64, sm3_hash);

    ret = TCM_Extend(index, sm3_hash, PCR_data);
    tcmPrintf("pcr data", 32, PCR_data);
    return ret;
}

int tcm_pcrread_test()
{
    int ret=0;
    BYTE index[4]={0x00,0x00,0x00,0x08};
    BYTE PCR_data[DIGEST_LEN];

    ret = TCM_PCRRead(index, PCR_data);
    tcmPrintf("pcr data", 32, PCR_data);
    return ret;
}

int tcm_pcrreset_test()
{
    int ret=0;
    BYTE index[8]={0x00,0x03,0x00,0x00,0x80};

    ret = TCM_PCR_Reset(index, 5);

    return ret;
}

int tcm_quote_test()
{
    int ret=0;
    BYTE pcr_data[128];
    uint32_t pcr_data_len=0;
    BYTE signed_data[128];
    uint32_t signed_len=0;
    BYTE index[8]={0x00,0x04,0x00,0x00,0x01,0x00};

    BYTE ownerAuth[32] = {0x00};  //授权值的sm3哈希值
    ownerAuthInit(OWNER_PASSWD, ownerAuth);

    BYTE offset[4]={0x00,0x00,0x00,0x00};
    BYTE sm2_key[69]={0x00};
    BYTE handle[4];

    ret = TCM_read_sm2_keyhandle_nv(ownerAuth, offset, sm2_key);
    if (ret)
    {
        printf("TCM_read_sm2_keyhandle_nv failed\n");
        return ret;
    }

    tcmPrintf("sm2 key", 69, sm2_key);
    memcpy(handle, sm2_key, 4);

    ret = TCM_Quote(ownerAuth, handle, index, 6, pcr_data, &pcr_data_len, signed_data, &signed_len);

    return ret;
}

int main(int argc, char** argv)
{
    int ret=0;
    int i=0;
    if (argc < 2)
    {
        printf("invalid parameter\n");
        return 0;
    }

    g_iDisplayFlag=1;
    for(i=0; i<argc; i++)
    {
        // 加上dd打印详细信息
        if(strcmp(argv[i], "/dd") == 0)
        {
            g_iDisplayFlag = 0;
            break;
        }
    }

    ret = FtdiSpiInit(SPI_BUS_FREQ, 0, SPI_DEV1_NAME);
    if(!ret)
    {
        fprintf(stderr, "Failed to initialize FTDI SPI\n");
        return -1;
    }
    else
    {
        /* code */
        printf("SPI init Success\n\n");
    }

    if (strcmp(argv[1], "/gad") == 0)
    {
        BYTE start_seq[4]={0x00,0x00,0x80,0x65};
        BYTE data[1024];
        uint32_t data_len=0;

        return TCM_GetAuditDigest(start_seq, data, &data_len);
    }

    if (strcmp(argv[1], "/fs") == 0)
    {
        BYTE res_type[4]={0x00,0x00,0x00,0x01};
        BYTE ownerAuth[32] = {0x00};
        ownerAuthInit(OWNER_PASSWD, ownerAuth);
        BYTE sm2_key[69]={0x00};
        BYTE key_handle[4]={0x00};
        BYTE offset[4]={0x00};

        ret = TCM_read_sm2_keyhandle_nv(ownerAuth, offset, sm2_key);
        if (ret)
            return ret;

        // tcmPrintf("sm2 key", 69, sm2_key);
        memcpy(key_handle, sm2_key, 4);

        return TCM_FlushSpecific(key_handle, res_type);
    }

    if (strcmp(argv[1], "/oc") == 0)
    {
        BYTE ownerAuth[DIGEST_LEN] = {0x00};
        ownerAuthInit(OWNER_PASSWD, ownerAuth);
        return TCM_OwnerClear(ownerAuth);
    }

    if (strcmp(argv[1], "/doc") == 0)
    {
        BYTE ownerAuth[DIGEST_LEN] = {0x00};
        ownerAuthInit(OWNER_PASSWD, ownerAuth);
        return TCM_DisableOwnerClear(ownerAuth);
    }

    if (strcmp(argv[1], "/pcre") == 0)
    {
        return pcrextend_test();
    }

    if (strcmp(argv[1], "/quo") == 0)
    {
        return tcm_quote_test();
    }

    if (strcmp(argv[1], "/pcrr") == 0)
    {
        return tcm_pcrread_test();
    }

    if (strcmp(argv[1], "/pcrs") == 0)
    {
        return tcm_pcrreset_test();
    }

    /* sm2验签，采用纯软件实现，输入参数为签名前的数据值，公钥，签名后的数据 */
    if (strcmp(argv[1], "/sm2vs") == 0)
    {
        return sm2_verify_signed();
    }

    if (strcmp(argv[1], "/vk") == 0)
    {
        ret = certify_key_test();
        return ret;
    }

    /* sm4加密，对文件加密 */
    if (strcmp(argv[1], "/sm4t0") == 0)
    {
        if (argc < 4)
        {
            printf("please input such as /sm4t0 file1 file2\n");
            return 1;
        }
        ret = sm4_encrypt_file(argv[2], argv[3]);
        return ret;
    }

    /* sm4解密，对文件解密 */
    if (strcmp(argv[1], "/sm4t1") == 0)
    {
        if (argc < 4)
        {
            printf("please input such as /sm4t1 file1 file2\n");
            return 1;
        }
        ret = sm4_decrypt_file(argv[2], argv[3]);
        return ret;
    }

    /* 对测试数据进行加密和解密 */
    if (strcmp(argv[1], "/sm4") == 0)
    {
        ret = sm4_en_decrypt();
        return ret;
    }
#if 1
    /* 完整的sm2签名流程 */
    if (strcmp(argv[1], "/sm2sf") == 0)
    {
        BYTE ownerAuth[DIGEST_LEN] = {0x00};  //授权值的sm3哈希值
        ownerAuthInit(OWNER_PASSWD, ownerAuth);

        BYTE hash[DIGEST_LEN]={0xfe,0xb9,0xc7,0xde,0xd4,0x30,0xcc,0x5d, 0xb0,0x29,0x25,0x51,0xf6,0xbb,0x4e,0xbe,
                       0xc7,0xde,0xd4,0x30,0xcc,0x5d,0xb0,0x29, 0x3e,0xb9,0xc7,0xde,0xd4,0x30,0x25,0x51};
        BYTE signed_data[64]={0x00};
        BYTE pubkey[65]={0x00};

        ret = TCM_Sign_full(ownerAuth, hash, signed_data, pubkey);
        if (ret == 0)
        {
            piece_data(hash, DIGEST_LEN, "hash");
            piece_data(pubkey, 65, "pub key");
            piece_data(signed_data, 64, "signed data");
        }

        return ret;
    }
#endif
    if (strcmp(argv[1], "/sm2s1") == 0)
    {
        ret = sm2_signed();
        return ret;
    }

    //startup，启动并新建nv空间，新建sm2密钥对并写入nv
    if(strcmp(argv[1], "/s0") == 0)
    {
        ret = TCM_device_init();
        if(0 == ret || 0x26 == ret)
        {
            printf("tcm env init Success\n");
        }
        else
        {
            printf("tcm env init Failed, ret=%d\n", ret);
            return ret;
        }
    }

    //仅启动tpcm，不新建nv空间
    if(strcmp(argv[1], "/s1") == 0)
    {
        ret = tcm_init();
        if(0 == ret || 0x26 == ret)
        {
            printf("tcm init Success\n");
        }
        else
        {
            printf("tcm init Failed, ret=%d\n", ret);
            return ret;
        }
    }

    if (strcmp(argv[1], "/ck") == 0)
    {
        ret = create_load_key();
        return ret;
    }
#if 1
    //sm3 soft，采用纯软件方式计算sm3哈希值
    if (strcmp(argv[1], "/ssm3") == 0)
    {
        if (argc<3)
        {
            printf("please input such as /ssm3 \"abcdefghijk\"\n");
            return 1;
        }
        uint8_t digest[DIGEST_LEN]={0x00};
        ret = TCM_SM3_soft(argv[2], strlen(argv[2]), digest);
        tcmPrintf("disgest:", DIGEST_LEN, digest);
        if (0 == ret)
        {
            printf("soft_sm3 start Success\n");
        }
        else
        {
            printf("soft_sm3 start Failed\n");
            return ret;
        }
        return 0;
    }

    //sm3，采用tpcm芯片计算sm3哈希值，与采用软件方式计算的值一致
    if (strcmp(argv[1], "/sm3") == 0)
    {
        if (argc<3)
        {
            printf("please input such as /sm3 \"abcdefghijk\"\n");
            return 1;
        }
        uint8_t digest[DIGEST_LEN] = {0x00};
        ret = TCM_SM3_start();
        if (0 == ret)
        {
            printf("TCM_sm3 start Success\n");
        }
        else
        {
            printf("TCM_sm3 start Failed, ret=%d\n", ret);
            return ret;
        }

        ret = TCM_SM3_complete(argv[2], strlen(argv[2]), digest);
        tcmPrintf("disgest:", DIGEST_LEN, digest);
        if (0 == ret)
        {
            printf("TCM_sm3 complete Success\n");
        }
        else
        {
            printf("TCM_sm3 complete Failed, ret=%d\n", ret);
            return ret;
        }
        return 0;
    }
#endif
    //forceClear 
    if (strcmp(argv[1], "/f") == 0)
    {
        ret = TCM_ForceClear();
        if (0 == ret)
        {
            printf("TCM_ForceClear Success\n");
        }
        else
        {
            printf("TCM_ForceClear Failed, ret=%d\n", ret);
            return ret;
        }
        return 0;
    }

    // disable force clear，断电恢复
    if (strcmp(argv[1], "/df") == 0)
    {
        ret = TCM_DisableForceClear();
        if (0 == ret)
        {
            printf("TCM_DisableForceClear Success\n");
        }
        else
        {
            printf("TCM_DisableForceClear Failed, ret=%d\n", ret);
            return ret;
        }
        return 0;
    }
#if 1
    //显示tpcm固件版本
    if (strcmp(argv[1], "/ve") == 0)
    {
        ret = TCM_GetVersion();
        if (0 == ret)
        {
            printf("TCM_GetVersion Success\n");
        }
        else
        {
            printf("TCM_GetVersion Failed\n");
            return ret;
        }
        return 0;
    }

    //使用 TCM_OwnerReadInternalPub 验证所有者授权码
    if (strcmp(argv[1], "/vp") == 0)
    {
        BYTE ownerAuth[DIGEST_LEN] = {0x00};  //授权值的sm3哈希值
        ownerAuthInit(OWNER_PASSWD, ownerAuth);

        BYTE ekPubData[65];
        ret = TCM_OwnerReadInternalPub(ownerAuth, ekPubData);
        if (0 == ret)
        {
            printf("TCM_OwnerReadInternalPub Success\n");
            tcmPrintf("EK Pub Data:", 65, ekPubData);
        }
        else
        {
            printf("TCM_OwnerReadInternalPub Failed\n");
        }
        return ret;
    }

    //take owner ship，创建新的密码，只能创建一次，重新创建前需要先强制清除
    if (strcmp(argv[1], "/np") == 0)
    {
        BYTE ownerAuth[DIGEST_LEN] = { 0x00 };
        ownerAuthInit(OWNER_PASSWD, ownerAuth);

        ret = TCM_TakeOwnership(ownerAuth);
        if (0 == ret)
        {
            printf("TCM_TakeOwnership Success\n");
        }
        else
        {
            printf("TCM_TakeOwnership Failed\n");
        }
        return ret;
    }
#endif
    //修改所有者的授权码
    if (strcmp(argv[1], "/cp") == 0)
    {
        if (argc < 4)
        {
            printf("please input such as /cp 123456 654321\n");
            return 1;
        }
        BYTE oldpassword[DIGEST_LEN];
        BYTE newpassword[DIGEST_LEN];
        char *a = argv[2];//old password
        ownerAuthInit(a, oldpassword);

        char* b = argv[3];//new password
        ownerAuthInit(b, newpassword);
        // tcmPrintf("oldpassword", DIGEST_LEN, oldpassword);
        // tcmPrintf("newpassword", DIGEST_LEN, newpassword);

        //verify the oldpassword begin
        //use ownerAuth to read pubEK公钥
        BYTE ekpubData[65];
        ret = TCM_OwnerReadInternalPub(oldpassword, ekpubData);
        if (0 != ret)
        {
            printf("oldpassword is not correct\n");
            return ret;
        }

        //verify old password end
        ret = TCM_ChangeAuthOwner(oldpassword, newpassword);
        if (0 == ret)
        {
            printf("TCM_ChangeAuthOwner Success\n");
        }
        else
        {
            printf("TCM_ChangeAuthOwner Failed\n");
            return ret;
        }
        return 0;
    }

    if (strcmp(argv[1], "/nvdef") == 0)
    {
        BYTE ownerAuth[DIGEST_LEN]={0x00};
        ownerAuthInit(OWNER_PASSWD, ownerAuth);

        ret = tcm_def_nv_tpcm(ownerAuth);
        return ret;
    }

    if (strcmp(argv[1], "/nvw") == 0)
    {
        if (argc < 3)
        {
            printf("please input such as /nvw tcm.bin\n");
            return 1;
        }
        BYTE ownerAuth[DIGEST_LEN]={0x00};
        ownerAuthInit(OWNER_PASSWD, ownerAuth);

        ret = tcm_write_file_tpcm(ownerAuth, argv[2]);
        return ret;
    }

    if (strcmp(argv[1], "/nvr") == 0)
    {
        // tcm策略文件长度为396字节
        BYTE data[396]={0x00};
        BYTE ownerAuth[DIGEST_LEN]={0x00};
        ownerAuthInit(OWNER_PASSWD, ownerAuth);

        ret = tcm_read_nv_tpcm(ownerAuth, data);
        tcmPrintf("nv data:", 396, data);
    }

    return 0;
}
