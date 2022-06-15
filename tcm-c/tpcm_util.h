#ifndef __TPCM_UTIL_H__
#define __TPCM_UTIL_H__

#include "common.h"
#include "tpcm_func.h"
#include "tcm_hash.h"

typedef struct __attribute__((__packed__)) {
    BYTE major;
    BYTE minor;
    BYTE revMajor;
    BYTE revMinor;
} TCM_version_t;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;  // 10 bytes
    uint32_t data_len;
    uint32_t version;
} tcm_version;

int TCM_GetVersion(void);

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    uint16_t entityType;
    uint32_t entityValue;
    BYTE nonce[DIGEST_LEN];
    BYTE inMac[DIGEST_LEN];
} in_buffer_apcreate;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
    BYTE ap_handle[4];
    BYTE tcm_nonce[DIGEST_LEN];
    BYTE seq[4];
    BYTE inMac[DIGEST_LEN];
} out_buff_apcreate;

/* 创建传输会话协议
入参：ownerAuth，entityType，entityValue
出参：sessionHandle，seq_APCreateOut，sessionKey
*/
int TCM_APCreate(BYTE ownerAuth[DIGEST_LEN], BYTE entityType[2], BYTE entityValue[4], 
    BYTE sessionHandle[4], BYTE seq_APCreateOut[4], BYTE sessionKey[DIGEST_LEN]);

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE ap_handle[4];
    BYTE inMac[DIGEST_LEN];
} in_buff_apterminate;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
} out_buff_apterminate;

/* 终止会话协议 */
int TCM_APTerminate(BYTE handle[4], BYTE seq[4], BYTE sessionKey[DIGEST_LEN], uint8_t flag);

void ownerAuthInit(char *a, BYTE *ownerAuth);

typedef struct __attribute__((__packed__))
{
    send_data_head head;
    BYTE data_len[4];    //要求获取的随机数长度，最长为1024
} in_buff_random;

typedef struct __attribute__((__packed__))
{
    rsp_data_head head;
    BYTE data_len[4];    //随机数长度，与要求的长度一致
    BYTE random[1024];   //能够获取的最长随机数为1024
} out_buff_random;

int TCM_GetRandom(BYTE data_len[4], BYTE random[1024]);

/* 入参：ownerAuth，pubEK
出参：encOwnerAuth
 */
int TCM_encOwnerAuth(BYTE ownerAuth[DIGEST_LEN], BYTE pubEK[65], BYTE encOwnerAuth[129]);

//---------------------------以下是在TPCM芯片上实现SM3功能-------------------------------------
int TCM_SM3_start(void);
int TCM_SM3_update(BYTE* content, size_t length);
int TCM_SM3_complete(BYTE* content, size_t length, BYTE digest[32]);
int TCM_SM3_completeExtend(BYTE* content, uint32_t length, BYTE PCR_index[4], 
    BYTE digest[DIGEST_LEN], BYTE PCR_result[DIGEST_LEN]);


typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE ek_handle[4];
    BYTE ap_handle[4];
    BYTE inMac[DIGEST_LEN];
} in_buff_readinpub;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
    BYTE resv0[4];
    BYTE resv1[2];
    BYTE resv2[2];
    BYTE resv3[4];
    BYTE resv4[4];

    BYTE ekpubdata_len[4];
    BYTE ekPubData[65];

    BYTE inMac[DIGEST_LEN];
} out_buff_readinpub;

int TCM_OwnerReadInternalPub(BYTE ownerAuth[DIGEST_LEN], BYTE ekPubData[65]);

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE nonce[DIGEST_LEN];
} in_buff_readpubek;

typedef out_buff_readinpub out_buff_readpubek;

int TCM_ReadPubEK(BYTE ekPubData[65]);

#endif
