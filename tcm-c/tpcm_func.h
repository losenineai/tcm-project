#ifndef __TPCM_FUNC_H__
#define __TPCM_FUNC_H__

#include "common.h"

//for tpcm nvindex
#define    TCM_NV_INDEX_TPCM_1       0x400000A0
#define    TCM_NV_INDEX_TPCM_2       0x400000A1

/* nv索引最多可以定义16个，索引值自定义，不和默认冲突就行 */
#define TCM_NV_INDEX_SM2_KEY_HANDLE  0x80000001
#define TCM_NV_INDEX_SM4_KEY_HANDLE  0x80000002


// TCM_NV_ATTRIBUTES values
#define TCM_NV_PER_OWNERWRITE        (1UL << 1)
#define TCM_NV_PER_AUTHWRITE         (1UL << 2) 
#define TCM_NV_PER_AUTH_READ         (1UL << 18)
#define TCM_NV_PER_OWNER_READ        (1UL << 17)
#define TCM_TAG_RQU_AUTH1_COMMAND    0x00c2

#define TCM_MAIN                     0x00008000
#define TCM_PROTECTED_COMMAND        0x00000000UL

#define TCM_PROTECTED_ORDINAL                 (TCM_PROTECTED_COMMAND | TCM_MAIN)
#define TCM_ORD_ChangeAuthOwner               (TCM_PROTECTED_ORDINAL + 16)


#define OWNER_PASSWD   "qwertyuiop"

typedef struct __attribute__((__packed__)) {
    uint16_t Tag;
    uint32_t total_len;
    uint32_t cmd;
} send_data_head;

typedef struct __attribute__((__packed__)) {
    uint16_t Tag;
    uint32_t total_len;
    uint32_t retcode;
} rsp_data_head;

//key tag
#define TCM_TAG_KEY    0x0015

//key usage A3.8
#define TCM_SM2KEY_SIGNING    0x0010
#define TCM_SM2KEY_STORAGE    0x0011
#define TCM_SM4KEY_STORAGE    0x0018
#define TCM_SM4KEY_BIND       0x0019


/* A3.10 key flags */
#define TCM_Migratable        0x00000002
#define TCM_isVolatile        0x00000004   //易失性密钥，在启动是不需要重新加载
#define TCM_PCRIgnoredOnRead  0x00000008

// auth data usage A3.9
#define TCM_AUTH_NEVER              0x00
#define TCM_AUTH_ALWAYS             0x01
#define TCM_AUTH_PRIV_USE_ONLY      0x03

/*
 * TCM_KEY_HANDLE    Reserved Key Handles 
 * These values specify specific keys or specific actions for the TCM.
 */
#define TCM_KH_SMK               0x40000000  //smk密钥句柄
#define TCM_KH_OWNER             0x40000001  //tcm所有者句柄
#define TCM_KH_REVOKE            0x40000002  //可撤销ek句柄
#define TCM_KH_TRANSPORT         0x40000003  //创建传输会话句柄
#define TCM_KH_OPERATOR          0x40000004  //操作者授权句柄
#define TCM_KH_EK                0x40000006  //ek句柄

#define AUTHTAG 0x00c2
#define TAG 0x00c1

#define TCM_KH_SRK  TCM_KH_SMK
#define TCM_ORD_SMS4Encrypt 0x000080c5
#define TCM_ORD_SMS4Decrypt 0x000080c6
#define TCM_ORD_CreateWrapKey 0x0000801f

#define TCM_ORD_Sign 0x0000803c
#define TCM_ET_KEYHANDLE 0x0001

/*
 * TCM_ALGORITHM_ID 
 * This table defines the types of algorithms which may be supported by the TCM.
 */ 
#define TCM_ALG_KDF              0x00000007  //kdf算法
#define TCM_ALG_XOR              0x0000000A  //异或算法
#define TCM_ALG_ECC              0x0000000B  //256ECC SM2非对称加密
#define TCM_ALG_SMS4             0x0000000C  //SM4 对称加密
#define TCM_ALG_SCH              0x0000000D  //sm3 哈希
#define TCM_ALG_HMAC             0x0000000E  //HMAC算法

#define TCM_ES_SM2      0x0006    //ecc加密编码
#define TCM_ES_SM2NONE  0x0004    //不能用于加密
#define TCM_ES_SM4_CBC  0x0008    //sm4对称cbc编码
#define TCM_ES_SM4_ECB  0x000a    //sm4对称ecb编码

#define TCM_SS_SM2NONE  0x0001    //不能用于签名
#define TCM_SS_SM2      0x0005    //sm2签名

typedef struct __attribute__((__packed__)) {
    BYTE resv1[4];    // 暂时不知道这两个变量的含义
    BYTE resv2[4];    //

    BYTE size[4];
    BYTE data[16];
} tcm_store_symkey;

typedef struct __attribute__((__packed__)) {
    BYTE algorithmID[4];
    BYTE encScheme[2];
    BYTE sigScheme[2];

    BYTE parmSize[4];
    tcm_store_symkey store_symkey;
} tcm_smk_key_parms;

typedef struct __attribute__((__packed__))
{
    BYTE tag[2];
    BYTE fill[2];
    BYTE key_usage[2];
    BYTE key_flags[4];
    BYTE auth_data_usage;

    tcm_smk_key_parms smk_key_parms;

    BYTE PCRInfoSize[4];
    BYTE* PCRInfo;      //指针长度为8
} tcm_smk_key;

int tcm_init(void);
int TCM_PhysicalEnable(void);
int TCM_PhysicalDisable(void);
int TCM_PhysicalSetActivated(void);
int TCM_PhysicalSetDeactivated(void);

int TCM_GetAuditDigest(BYTE start_seq[4], BYTE data[1024], uint32_t* data_len);
int TCM_FlushSpecific(BYTE res_handle[4], BYTE res_type[4]);

int TCM_ForceClear(void);
int TCM_DisableForceClear(void);

int TCM_OwnerClear(BYTE ownerAuth[DIGEST_LEN]);
int TCM_DisableOwnerClear(BYTE ownerAuth[DIGEST_LEN]);

int TCM_OwnerReadInternalPub(BYTE ownerAuth[DIGEST_LEN], BYTE ekPubData[65]);
int TCM_ReadPubEK(BYTE ekPubData[65]);

/* 读取pcr，入参为index，含义为pcr索引，出参为pcr_data，含义为pcr值 */
int TCM_PCRRead(BYTE index[4], BYTE PCR_data[DIGEST_LEN]);

/* 写入PCR，入参为index,didgst，含义分别为pcr索引，输入摘要值，出参为new_value，含义为新的度量值 */
int TCM_Extend(BYTE index[4], BYTE digest[DIGEST_LEN], BYTE new_value[DIGEST_LEN]);

/* 复位PCR，入参为index和index_len，分别为目标pcr index及index长度 */
int TCM_PCR_Reset(BYTE* index, uint32_t index_len);

int TCM_Quote(BYTE ownerAuth[DIGEST_LEN], BYTE key_handle[4], BYTE* index, uint32_t index_len,
    BYTE pcr_data[128], uint32_t* pcr_data_len, BYTE signed_data[128], uint32_t* signed_len);

int TCM_ChangeAuthOwner(BYTE oldpassword[DIGEST_LEN], BYTE newpassword[DIGEST_LEN]);

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE nvIndex[4];
    BYTE offset[4];
    BYTE data_len[4];
    BYTE sessionhandle[4];
    BYTE HMAC[DIGEST_LEN];
} in_buff_NV_read;

// int TCM_NV_DefineSpace(BYTE ownerAuth[DIGEST_LEN], BYTE nvIndex[4], BYTE nvSize[4], BYTE attribute[4]);
// int TCM_NV_WriteValueAuth(BYTE ownerAuth[DIGEST_LEN], BYTE index[4], BYTE offset[4], BYTE nvSize[4], BYTE *buffer_Data);
// int TCM_NV_ReadValueAuth(BYTE ownerAuth[DIGEST_LEN], BYTE index[4], BYTE offset[4], BYTE nvSize[4], BYTE *buffer_Data);

int tcm_def_nv_tpcm(BYTE ownerAuth[DIGEST_LEN]);
int tcm_write_file_tpcm(BYTE ownerAuth[DIGEST_LEN], char* filename);
int tcm_read_nv_tpcm(BYTE ownerAuth[DIGEST_LEN], BYTE data[396]);

int TCM_write_sm2_keyhandle_nv(BYTE ownerAuth[DIGEST_LEN], BYTE offset[4], BYTE sm2_key[69]);
int TCM_read_sm2_keyhandle_nv(BYTE ownerAuth[DIGEST_LEN], BYTE offset[4], BYTE sm2_key[69]);

int TCM_TakeOwnership(BYTE ownerAuth[DIGEST_LEN]);

typedef struct __attribute__((__packed__)) {
    BYTE algorithmID[4];
    BYTE encScheme[2];
    BYTE sigScheme[2];
    BYTE parmSize[4];
    BYTE keyLength[4];
} TCM_SM2_KEY_PARMS;

typedef struct __attribute__((__packed__)) {
    BYTE tag[2];
    BYTE fill[2];
    BYTE key_usage[2];
    BYTE key_flags[4];
    BYTE auth_data_usage;

    TCM_SM2_KEY_PARMS sm2_parms;

    BYTE PCRInfoSize[4];
    BYTE* PCRInfo;      //指针长度为8
} TCM_SM2_KEY;

typedef struct __attribute__((__packed__))
{
    rsp_data_head head;
    BYTE key_out[248];
    BYTE inMac[DIGEST_LEN];
} out_buff_createwrapkey;

int TCM_CreateWrapKey(BYTE ownerAuth[DIGEST_LEN], BYTE key_out[248], BYTE pubkey[65]);

typedef struct __attribute__((__packed__))
{
    rsp_data_head head;
    BYTE handle[4];
    BYTE inMac[DIGEST_LEN];
} out_buff_loadkey;

int TCM_LoadKey(BYTE ownerAuth[DIGEST_LEN], BYTE key[256], uint32_t key_len, BYTE key_handle[4]);
int TCM_CertifyKey(BYTE key_handle[4], BYTE about_key_handle[4]);

/* 直接将sm4 key写入nv */
int write_sm4_key(BYTE ownerAuth[DIGEST_LEN], BYTE key[16]);
/* 从nv中读取sm4 key info，包括key句柄和key信息 */
int TCM_read_sm4_keyhandle_nv(BYTE ownerAuth[DIGEST_LEN], BYTE offset[4], BYTE sm4_key[20]);
int TCM_write_sm4_keyhandle_nv(BYTE ownerAuth[DIGEST_LEN], BYTE offset[4], BYTE sm4_key[20]);
#if 1
typedef struct __attribute__((__packed__)) {
    BYTE algorithmID[4];
    BYTE encScheme[2];
    BYTE sigScheme[2];
    BYTE parmSize[4];
    BYTE len[4];
    BYTE keyLength[4];
    BYTE key[65];
} tcm_sm2_pubkey;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
    tcm_sm2_pubkey pubkey;
    BYTE inMac[DIGEST_LEN];
} out_buff_getpubkey;

/* get pub key暂时不使用，公钥可以从创建sm2返回信息中直接获得，与使用该接口获得的公钥一致 */
int TCM_GetPubKey(BYTE ownerAuth[DIGEST_LEN], BYTE key_handle[4], BYTE pubkey[65]);
#endif
int TCM_WrapKey(BYTE ownerAuth[DIGEST_LEN], BYTE sm4Key[16], BYTE wrapKeyInfo[159]);

int TCM_SM4Encrypt(BYTE key_handle[4], BYTE IV[16], 
    BYTE data[MAX_BUFSIZE], uint32_t data_len, BYTE enc_data[MAX_BUFSIZE], uint32_t* enc_data_len);
int TCM_SM4Decrypt(BYTE key_handle[4], BYTE IV[16],
    BYTE enc_data[MAX_BUFSIZE], uint32_t enc_data_len, BYTE data[MAX_BUFSIZE], uint32_t* data_len);

int TCM_Sign(BYTE key_handle[4], BYTE data[DIGEST_LEN], BYTE signed_data[64]);
int TCM_Sign_full(BYTE ownerAuth[DIGEST_LEN], BYTE data[DIGEST_LEN], BYTE signed_data[64], BYTE pubkey[65]);

int init_sm2_key(BYTE ownerAuth[DIGEST_LEN]);
int TCM_device_init(void);

int TCM_SetCapability(void);
int TCM_GetCapability(BYTE capability[16], uint32_t* capa_len);
int TCM_SelfTestFull(void);
int TCM_GetTestResult(void);
int TCM_GetTicks(void);

#endif
