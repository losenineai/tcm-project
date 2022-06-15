#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tcm_ecc.h"
#include "tcm_hash.h"
#include "common.h"
#include "tpcm_func.h"
#include "ftdi_spi_tpm.h"
#include "tpcm_util.h"

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE type[2];
} in_buff_startup;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
} out_buff_startup;

static int TCM_Startup(void)
{
    int ret=0;
    BYTE  outBuffer[MAX_BUFSIZE]={0x00};
    uint32_t outBufferLength=MAX_BUFSIZE;
    in_buff_startup in_buff;
    out_buff_startup out_buff;

    //1.Tag
    BYTE Tag[2]={0x00,0xC1};
    BYTE sizeStartup[4]={0x00,0x00,0x00,0x0c};
    BYTE cmdStartup[4]={0x00,0x00,0x80,0x99};
    BYTE type1[2]={0x00,0x01};  //所有变量设置为缺省值，需重新设置向量
    BYTE type2[2]={0x00,0x02};  //使tcm恢复到以前执行tcm_savestate所保存的值
    BYTE type3[2]={0x00,0x03};  //使tcm无效的启动方式，需重新执行tcm_init才能是tcm进入正常工作状态

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, sizeStartup, 4);
    memcpy(&in_buff.head.cmd, cmdStartup, 4);
    memcpy(&in_buff.type, type1, 2);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff));
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if(ret == 0 || 0x26 == ret)
    {
    }
    else
    {
        printf("%s Error code:%d\n", __func__, ret);
    }

    return ret;
}

int TCM_SaveState(void)
{
    int ret = 0;
    BYTE  outBuffer[MAX_BUFSIZE];
    uint32_t  outBufferLength=MAX_BUFSIZE;
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    //enable
    BYTE    cmdPhysicalEnable[10] = {0x00,0xc1, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x80,0x98};

    Tddli_TransmitData(cmdPhysicalEnable, sizeof(cmdPhysicalEnable), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if(ret==0)
    {
        // printf("%s success\n", __func__);
    }
    else
    {
        printf("%s Error code:%d\n", __func__, ret);
    }

    return ret;
}

//2.TCM_PhysicalEnable
int TCM_PhysicalEnable(void)
{
    int ret = 0;
    BYTE  outBuffer[MAX_BUFSIZE];
    uint32_t  outBufferLength=MAX_BUFSIZE;
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    //enable
    BYTE    cmdPhysicalEnable[10] = {0x00,0xc1, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x80,0x6f};

    Tddli_TransmitData(cmdPhysicalEnable, sizeof(cmdPhysicalEnable), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if(ret==0)
    {
        // printf("Command PhysicalEnable success\n");
    }
    else
    {
        printf("Command PhysicalEnable Failed, ret=%d\n", ret);
    }

    return ret;
}

int TCM_PhysicalDisable(void)
{
    int ret = 0;
    BYTE  outBuffer[MAX_BUFSIZE];
    uint32_t  outBufferLength=MAX_BUFSIZE;
    memset(outBuffer, 0x00, MAX_BUFSIZE); 
    //disable
    BYTE    cmdPhysicalDisable[10] = {0x00,0xc1, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x80,0x70};

    Tddli_TransmitData(cmdPhysicalDisable, sizeof(cmdPhysicalDisable), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if(ret == 0)
    {
        // printf("Command PhysicalDisable success\n");
    }
    else
    {
        printf("Command PhysicalDisable Failed, ret=%d\n", ret);
    }

    return ret;
}

int TCM_PhysicalSetActivated(void)
{ 
    int ret = 0;
    BYTE outBuffer[MAX_BUFSIZE];
    BYTE cmdPhysicalActivate[11] = {0x00,0xc1, 0x00,0x00,0x00,0x0b, 0x00,0x00,0x80,0x72, 0x00};

    uint32_t outBufferLength=MAX_BUFSIZE;
    memset(outBuffer, 0x00, MAX_BUFSIZE); 
    Tddli_TransmitData(cmdPhysicalActivate, sizeof(cmdPhysicalActivate), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if (ret == 0)
    {
        // printf("%s success\n", __func__);
    }
    else
    {
        printf("%s, Error code:%d\n", __func__, ret);
    }

    return ret;
}

int TCM_PhysicalSetDeactivated(void)
{ 
    int ret = 0;
    BYTE outBuffer[MAX_BUFSIZE];
    BYTE cmdPhysicalActivate[11] = {0x00,0xc1, 0x00,0x00,0x00,0x0b, 0x00,0x00,0x80,0x72, 0x01};

    uint32_t outBufferLength=MAX_BUFSIZE;
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    Tddli_TransmitData(cmdPhysicalActivate, sizeof(cmdPhysicalActivate), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if (ret == 0)
    {
        // printf("%s success\n", __func__);
    }
    else
    {
        printf("%s, Error code:%d\n", __func__, ret);
    }

    return ret;
}

typedef struct __attribute__((__packed__))
{
    send_data_head head;
    BYTE start_seq[4];
} in_buff_auditdidgst;

typedef struct __attribute__((__packed__))
{
    rsp_data_head head;
    BYTE audit_counter[10];
    BYTE audit_digest[DIGEST_LEN];
    BYTE flag[1];
    BYTE data_len[4];
    BYTE data[1024];
} out_buff_auditdidgst;

int TCM_GetAuditDigest(BYTE start_seq[4], BYTE data[1024], uint32_t* data_len)
{
    int ret=0;
    in_buff_auditdidgst in_buff;
    out_buff_auditdidgst out_buff;
    BYTE outBuffer[MAX_BUFSIZE];
    uint32_t outBufferLength=0;

    BYTE Tag[2]={0x00,0xc1};
    BYTE size[4]={0x00,0x00,0x00,0x0e};
    BYTE cmd[4]={0x00,0x00,0x80,0x85};

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.start_seq, start_seq, 4);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_auditdidgst), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, Unpack32(outBuffer+2));
    ret = Unpack32(outBuffer + 6);
    if (ret)
    {
        printf("%s, Error code:%d\n", __func__, ret);
    }
    else
    {
        *data_len = Unpack32(out_buff.data_len);
        if (*data_len)
            memcpy(data, out_buff.data, *data_len);
    }

    return ret;
}

typedef struct __attribute__((__packed__))
{
    send_data_head head;
    BYTE ap_handle[4];
    BYTE inMac[DIGEST_LEN];
} in_buff_ownerclear;

typedef struct __attribute__((__packed__))
{
    rsp_data_head head;
    BYTE inMac[DIGEST_LEN];
} out_buff_ownerclear;

/* 清除所有者授权信息 */
int TCM_OwnerClear(BYTE ownerAuth[DIGEST_LEN])
{
    in_buff_ownerclear in_buff;
    out_buff_ownerclear out_buff;
    BYTE outBuffer[4096];
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;
    BYTE Tag[2]={0x00,0xc2};
    BYTE size[4]={0x00,0x00,0x00,0x2e};
    BYTE cmd[4]={0x00,0x00,0x80,0x5b};
    BYTE hash[DIGEST_LEN];

    BYTE entityType[2]={0x00,0x02};
    BYTE entityValue[4]={0x00};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    //ownerAuth为授权值的hash结果
    ret = TCM_APCreate(ownerAuth, entityType, entityValue, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate failed, ret=%d\n", ret);
        return ret;
    }

    TCM_SM3_soft(cmd, 4, hash);
    BYTE data[36];
    BYTE inMac[DIGEST_LEN];
    memcpy(data, hash, DIGEST_LEN);
    memcpy(data+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(data, 36, sessionKey, DIGEST_LEN, inMac);

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.ap_handle, handle_APCreateOut, 4);
    memcpy(&in_buff.inMac, inMac, DIGEST_LEN);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_ownerclear), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer+6);
    if (ret)
    {
        printf("%s failed\n", __func__);
    }

    //清除授权信息后，无法执行终止会话协议
    // ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 0);

    return ret;
}

typedef in_buff_ownerclear in_buff_disableownerclear;
typedef out_buff_ownerclear out_buff_disableownerclear;

int TCM_DisableOwnerClear(BYTE ownerAuth[DIGEST_LEN])
{
    in_buff_disableownerclear in_buff;
    out_buff_disableownerclear out_buff;
    BYTE outBuffer[4096];
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;
    BYTE Tag[2]={0x00,0xc2};
    BYTE size[4]={0x00,0x00,0x00,0x2e};
    BYTE cmd[4]={0x00,0x00,0x80,0x5c};
    BYTE hash[DIGEST_LEN];

    BYTE entityType[2]={0x00,0x02};
    BYTE entityValue[4]={0x00};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    //ownerAuth为授权值的hash结果
    ret = TCM_APCreate(ownerAuth, entityType, entityValue, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate failed, ret=%d\n", ret);
        return ret;
    }

    TCM_SM3_soft(cmd, 4, hash);
    BYTE data[36];
    BYTE inMac[DIGEST_LEN];
    memcpy(data, hash, DIGEST_LEN);
    memcpy(data+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(data, 36, sessionKey, DIGEST_LEN, inMac);

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.ap_handle, handle_APCreateOut, 4);
    memcpy(&in_buff.inMac, inMac, DIGEST_LEN);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_ownerclear), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer+6);
    if (ret)
    {
        printf("%s failed\n", __func__);
    }

    //清除授权信息后，无法执行终止会话协议
    // ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 0);

    return ret;
}

//3.TCM_ForceClear
int TCM_ForceClear(void)
{
    BYTE outBuffer[4096];
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;

    BYTE cmdForceClear[10] = {0x00,0xc1, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x80,0x5d};

    Tddli_TransmitData(cmdForceClear, sizeof(cmdForceClear), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if(ret==0)
    {
        // printf("Command %s success\n", __func__);
    }
    else
    {
        printf("Command %s Error code:%d\n", __func__, ret);
    }

    return ret;
}

//3.TCM_DisableForceClear
int TCM_DisableForceClear(void)
{
    BYTE outBuffer[4096];
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;

    BYTE cmdDisableForceClear[10] = {0x00,0xc1, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x80,0x5e};

    Tddli_TransmitData(cmdDisableForceClear,sizeof(cmdDisableForceClear), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if(ret==0)
    {
        // printf("Command %s success\n", __func__);
    }
    else
    {
        printf("Command %s Error code:%d\n", __func__, ret);
    }

    return ret;
}

int TCM_SelfTestFull(void)
{
    BYTE outBuffer[4096];
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;
    BYTE TCM_SelfTestFull[10] = {0x00,0xc1, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x80,0x50};

    Tddli_TransmitData(TCM_SelfTestFull,sizeof(TCM_SelfTestFull), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if(ret==0)
    {
        // printf("Command %s success\n", __func__);
    }
    else
    {
        printf("Command %s Error code:%d\n", __func__, ret);
    }

    return ret;
}

int TCM_GetTestResult(void)
{
    BYTE outBuffer[4096];
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;

    BYTE    GetTestResult[10] = {0x00,0xc1, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x80,0x54};

    Tddli_TransmitData(GetTestResult, sizeof(GetTestResult), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if(ret==0)
    {
        // printf("Command %s success\n", __func__);
    }
    else
    {
        printf("Command %s Error code:%d\n", __func__, ret);
    }

    return ret;
}

int TCM_GetTicks(void)
{
    BYTE outBuffer[4096];
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;

    BYTE    cmdGetTicks[10] = {0x00,0xC1, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x80,0xf1};

    Tddli_TransmitData(cmdGetTicks, sizeof(cmdGetTicks), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer+6);
    if(ret ==0)
    {
        // printf("Command %s success\n", __func__);
    }
    else
    {
        printf("Command %s Error, code:%d\n", __func__, ret);
    }

    return ret;
}

typedef struct __attribute__((__packed__))
{
    send_data_head head;
    BYTE res_handle[4];
    BYTE res_type[4];
} in_buff_flushspecific;

int TCM_FlushSpecific(BYTE res_handle[4], BYTE res_type[4])
{
    in_buff_flushspecific in_buff;
    BYTE outBuffer[4096];
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;

    BYTE Tag[2]={0x00,0xC1};
    BYTE size[4]={0x00,0x00,0x00,0x12};
    BYTE cmd[4]={0x00,0x00,0x80,0xba};

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.res_handle, res_handle, 4);
    memcpy(&in_buff.res_type, res_type, 4);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_flushspecific), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer+6);
    if (ret)
    {
        printf("Command %s Error, code:%d\n", __func__, ret);
    }

    return ret;
}

int TCM_GetCapability(BYTE capability[16], uint32_t* capa_len)
{
    int ret = 0;
    BYTE  outBuffer[MAX_BUFSIZE];
    uint32_t  outBufferLength=MAX_BUFSIZE;
    memset(outBuffer, 0x00, MAX_BUFSIZE); 
    BYTE    cmdGetCapability[22] = {0x00,0xc1, 0x00,0x00,0x00,0x16, 0x00,0x00,0x80,0x65, 0x00,0x00,0x00,0x07,
                                    0x00,0x00,0x00,0x04, 0x00,0x00,0x00,0x01};

    Tddli_TransmitData(cmdGetCapability, sizeof(cmdGetCapability), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if(ret == 0)
    {
        // printf("Command %s success\n", __func__);
        *capa_len = Unpack32(outBuffer+10);
        memcpy(capability, outBuffer+14, *capa_len);
    }
    else
    {
        printf("Command %s Failed, ret=%d\n", __func__, ret);
    }

    return ret;
}

int TCM_SetCapability(void)
{
    int ret = 0;
    BYTE  outBuffer[MAX_BUFSIZE];
    uint32_t  outBufferLength=MAX_BUFSIZE;
    memset(outBuffer, 0x00, MAX_BUFSIZE); 
    BYTE cmdSetCapability[27] = {0x00,0xc1, 0x00,0x00,0x00,0x1b, 0x00,0x00,0x80,0x3f, 0x00,0x00,0x00,0x05,
                                 0x00,0x00,0x00,0x04, 0x00,0x00,0x00,0x04, 0x00,0x00,0x00,0x01, 0x00};

    Tddli_TransmitData(cmdSetCapability, sizeof(cmdSetCapability), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if(ret == 0)
    {
        // printf("Command %s success\n", __func__);
    }
    else
    {
        printf("Command %s Failed, ret=%d\n", __func__, ret);
    }

    return ret;
}

typedef struct __attribute__((__packed__))
{
    send_data_head head;
    BYTE PCRIndex[4];
} in_buff_pcrread;

typedef struct __attribute__((__packed__))
{
    rsp_data_head head;
    BYTE PCR_data[DIGEST_LEN];
} out_buff_pcrread;

/* 读取pcr，入参为index，含义为pcr索引，出参为pcr_data，含义为pcr值 */
int TCM_PCRRead(BYTE index[4], BYTE PCR_data[DIGEST_LEN])
{
    int iret=0;
    BYTE outBuffer[MAX_BUFSIZE];
    uint32_t outBufferLength = MAX_BUFSIZE;
    in_buff_pcrread in_buff;
    out_buff_pcrread out_buff;

    BYTE Tag[2]={0x00,0xc1};
    BYTE size[4]={0x00,0x00,0x00,0x0e};
    BYTE cmd[4]={0x00,0x00,0x80,0x15};

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.PCRIndex, index, 4);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_pcrread), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff_pcrread));
    iret = reverse_bytes_uint32(out_buff.head.retcode);
    if (0 == iret)
    {
        // printf("cmd PCR read success\n");
        memcpy(PCR_data, out_buff.PCR_data, DIGEST_LEN);
    }
    else
    {
        printf("cmd PCR read failed, ret=%d\n", iret);
    }

    return iret;
}

typedef struct __attribute__((__packed__))
{
    send_data_head head;
    BYTE PCRIndex[4];
    BYTE digest[DIGEST_LEN];
} in_buff_extend;

typedef struct __attribute__((__packed__))
{
    rsp_data_head head;
    BYTE new_value[DIGEST_LEN];
} out_buff_extend;

/* 写入PCR，入参为index,didgst，含义分别为pcr索引，输入摘要值，出参为new_value，含义为新的度量值 */
int TCM_Extend(BYTE index[4], BYTE digest[DIGEST_LEN], BYTE new_value[DIGEST_LEN])
{
    int iret=0;
    BYTE outBuffer[MAX_BUFSIZE];
    uint32_t outBufferLength = MAX_BUFSIZE;
    in_buff_extend in_buff;
    out_buff_extend out_buff;

    BYTE Tag[2]={0x00,0xc1};
    BYTE size[4]={0x00,0x00,0x00,0x2e};
    BYTE cmd[4]={0x00,0x00,0x80,0x14};

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.PCRIndex, index, 4);
    memcpy(&in_buff.digest, digest, DIGEST_LEN);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_extend), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff_extend));
    iret = reverse_bytes_uint32(out_buff.head.retcode);
    if (0 == iret)
    {
        // printf("cmd tcm extend success\n");
        memcpy(new_value, out_buff.new_value, DIGEST_LEN);
    }
    else
    {
        printf("cmd PCR read failed, ret=%d\n", iret);
    }

    return iret;
}

/* 引用PCR，TCM_Quote
 * 入参：ownerAuth：所有者授权信息，key_handle：签名密钥句柄，index及index_len：PCR索引及长度
 * pcr_data及pcr_data_len：pcr数据及长度，signed_data及signed_len：签名数据及长度
 */
int TCM_Quote(BYTE ownerAuth[DIGEST_LEN], BYTE key_handle[4], BYTE* index, uint32_t index_len,
    BYTE pcr_data[128], uint32_t* pcr_data_len, BYTE signed_data[128], uint32_t* signed_len)
{
    int ret=0;
    BYTE inBuffer[MAX_BUFSIZE]={0x00};
    uint32_t in_buff_len=0;
    BYTE outBuffer[MAX_BUFSIZE]={0x00};
    uint32_t out_buff_len=MAX_BUFSIZE;
    BYTE ownerAuth1[DIGEST_LEN]={0x00};

    BYTE Tag[2]={0x00,0xc2};
    BYTE size[4]={0};
    BYTE cmd[4]={0x00,0x00,0x80,0x16};
    BYTE inMac[DIGEST_LEN]={0x00};
    BYTE hmac_Text[128]={0x00};
    BYTE anti_attack[DIGEST_LEN]={0x00};

    BYTE entityType[2]={0x00,0x02};
    BYTE entityValue[4]={0x00};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    //ownerAuth为授权值的hash结果
    ret = TCM_APCreate(ownerAuth, entityType, entityValue, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate Failed! ret=%d\n", ret);
        return ret;
    }

    memcpy(inBuffer, Tag, 2);
    in_buff_len += 2;
    in_buff_len += 4;
    memcpy(inBuffer + in_buff_len, cmd, 4);
    in_buff_len += 4;
    memcpy(inBuffer + in_buff_len, key_handle, 4);
    in_buff_len += 4;
    memcpy(inBuffer + in_buff_len, anti_attack, DIGEST_LEN);
    in_buff_len += 32;
    memcpy(inBuffer + in_buff_len, index, index_len);
    in_buff_len += index_len;
    memcpy(inBuffer + in_buff_len, handle_APCreateOut, 4);
    in_buff_len += 4;

    BYTE data[52]={0x00};
    uint32_t data_len=0;
    BYTE hash[DIGEST_LEN]={0x00};

    memcpy(data, cmd, 4);
    data_len += 4;
    memcpy(data + data_len, anti_attack, DIGEST_LEN);
    data_len += DIGEST_LEN;
    memcpy(data + data_len, index, index_len);
    data_len += index_len;
    TCM_SM3_soft(data, data_len, hash);

    memcpy(hmac_Text, hash, DIGEST_LEN);
    memcpy(hmac_Text+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(hmac_Text, 36, sessionKey, DIGEST_LEN, inMac);

    memcpy(inBuffer + in_buff_len, inMac, DIGEST_LEN);
    in_buff_len += DIGEST_LEN;

    Pack32(size, in_buff_len);
    memcpy(inBuffer + 2, size, 4);

    Tddli_TransmitData(inBuffer, in_buff_len, outBuffer, &out_buff_len);
    ret = Unpack32(outBuffer+6);
    if (ret == 0)
    {
        // printf("%s success\n", __func__);
    }
    else
    {
        printf("%s failed\n", __func__);
    }

    ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 0);
    if (ret != 0)
    {
        printf("TCM_NV_APTerminate Error!, ret=%d\n", ret);
    } else {
        // printf("TCM_NV_APTerminate success\n");
    }

    return ret;
}

/* 复位PCR，入参为index和index_len，分别为目标pcr及目标pcr的长度 */
int TCM_PCR_Reset(BYTE* index, uint32_t index_len)
{
    int iret=0;
    BYTE outBuffer[MAX_BUFSIZE];
    uint32_t outBufferLength = MAX_BUFSIZE;
    BYTE in_buff[32];
    uint32_t in_buff_len=0;

    BYTE Tag[2]={0x00,0xc1};
    BYTE size[4]={0};
    BYTE cmd[4]={0x00,0x00,0x80,0xc8};

    memcpy(in_buff, Tag, 2);
    in_buff_len += 2;
    in_buff_len += 4;
    memcpy(in_buff + in_buff_len, cmd, 4);
    in_buff_len += 4;
    memcpy(in_buff + in_buff_len, index, index_len);
    in_buff_len += index_len;

    Pack32(size, in_buff_len);
    memcpy(in_buff + 2, size, 4);

    Tddli_TransmitData(in_buff, in_buff_len, outBuffer, &outBufferLength);
    iret = Unpack32(outBuffer+6);
    if (iret == 0)
    {
        printf("%s success\n", __func__);
    }
    else
    {
        printf("%s failed\n", __func__);
    }
    return iret;
}

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    uint16_t protocol;
    BYTE newpassword[DIGEST_LEN];
    uint16_t entityType;
    BYTE ap_handle[4];
    BYTE inMac[DIGEST_LEN];
} in_buff_changeauthowner;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
    BYTE inMac[DIGEST_LEN];
} out_buff_changeauthowner;

/* 5.8.2 更改所有者/存储主密钥授权数据 */
int TCM_ChangeAuthOwner(BYTE oldpassword[DIGEST_LEN], BYTE newpassword[DIGEST_LEN])
{
    BYTE outBuffer[MAX_BUFSIZE];
    uint32_t outBufferLength;
    int ret;

    //1.APCreate
    BYTE AuthTag[2]={0x00,0xC2};
    BYTE size_APCreate[4] = {0x00,0x00,0x00,0x50};
    BYTE cmd_APCreate[4] = {0x00,0x00,0x80,0xBF};
    BYTE entityType[2] = {0x00,0x02};
    BYTE entityValue[4] = {0x40,0x00,0x00,0x01};
    BYTE ap_handle[4];
    BYTE seq[4];
    BYTE hmac_Text[128]={0x00};
    BYTE inMac[DIGEST_LEN]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    ret = TCM_APCreate(oldpassword, entityType, entityValue, ap_handle, seq, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate Failed! ret=%d\n", ret);
        return ret;
    }

    in_buff_changeauthowner in_buff;
    out_buff_changeauthowner out_buff;

    BYTE Tag[2]={0x00,0xc2};
    BYTE size[4]={0x00,0x00,0x00,0x52};
    BYTE cmd[4]={0x00,0x00,0x80,0x10};
    BYTE protocol[2]={0x00,0x04};

    //make newencAuth
    BYTE newAuth[DIGEST_LEN];
    BYTE text[40];
    BYTE newEncAuth[DIGEST_LEN]={0x00};

    memcpy(text, sessionKey, DIGEST_LEN);
    memcpy(text+DIGEST_LEN, seq, 4);
    TCM_SM3_soft(text, 36, newEncAuth);

    memcpy(newAuth, newpassword, DIGEST_LEN);
    for(int i = 0;i < DIGEST_LEN;i++)
    {
        newEncAuth[i] = newAuth[i] ^ newEncAuth[i];
    }

    //8.hmac
    BYTE hashResult[DIGEST_LEN];
    memset(hashResult, 0x00, DIGEST_LEN);

    memcpy(text, cmd, 4);
    memcpy(text+4, protocol, 2);
    memcpy(text+6, newEncAuth, DIGEST_LEN);
    memcpy(text+38, entityType, 2);
    TCM_SM3_soft(text, 40, hashResult);

    memset(hmac_Text, 0x00, sizeof(hmac_Text));
    memcpy(hmac_Text, hashResult, DIGEST_LEN);
    memcpy(hmac_Text+DIGEST_LEN, seq, 4);
    tcm_hmac(hmac_Text, 36, sessionKey, DIGEST_LEN, inMac);

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.protocol, protocol, 2);
    memcpy(&in_buff.newpassword, newEncAuth, DIGEST_LEN);
    memcpy(&in_buff.entityType, entityType, 2);
    memcpy(&in_buff.ap_handle, ap_handle, 4);
    memcpy(&in_buff.inMac, inMac, DIGEST_LEN);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_changeauthowner), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff_changeauthowner));
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if(ret != 0)
    {
        printf("TCM_ChangeOwnerAuth Failed, ret=%d\n", ret);
    }
    // 这里不需要执行终止会话协议的命令，因为修改了owner passwd，无法执行
    // ret = TCM_APTerminate(ap_handle, seq, sessionKey, 0);
    // 报错误码34，使用无效的句柄

    return ret;
}

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    uint16_t TagNV;
    uint32_t NVIndex;

    uint16_t TagPCRinfo1;
    uint16_t PCRresv1;
    uint16_t sizeOfSelect1;
    uint16_t pcrSelect1;
    uint16_t sizeOfSelect2;
    uint16_t pcrSelect2;

    BYTE digestAtCreation1[DIGEST_LEN];
    BYTE digestAtRelease1[DIGEST_LEN];

    uint16_t TagPCRinfo2;
    uint16_t PCRresv2;
    uint16_t sizeOfSelect3;
    uint16_t pcrSelect3;
    uint16_t sizeOfSelect4;
    uint16_t pcrSelect4;

    BYTE digestAtCreation2[DIGEST_LEN];
    BYTE digestAtRelease2[DIGEST_LEN];

    BYTE TagNVAttribute[2];
    BYTE NVpermission[4];
    BYTE resv[3];
    BYTE nvSize[4];   // 到这里长度为181

    BYTE encAuth[DIGEST_LEN];
    BYTE sessionhandle[4];
    BYTE HMAC[DIGEST_LEN];
} in_buff_definenvspace;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
    BYTE inMac[DIGEST_LEN];
} out_buff_definenvspace;

/* 自定义nv空间，最多16个nv，每个nv的索引index不能一样，不能和系统用于主动度量的nv一样，每个nv空间最大为1004 */
static int TCM_NV_DefineSpace(BYTE ownerAuth[DIGEST_LEN], BYTE nvIndex[4], BYTE nvSize[4], BYTE attribute[4])
{
    BYTE outBuffer[MAX_BUFSIZE]={0x00};
    uint32_t outBufferLength=0;
    int ret = 0;
    int ErrorFlag = 0;
    uint16_t i=0;
    BYTE hmac_Text[64] = {0x00};
    BYTE hmac_inMac[DIGEST_LEN] = {0x00};
    BYTE session_key[DIGEST_LEN]={0x00};
    BYTE sessionHandle[4] = {0x00};
    BYTE seq_APCreateOut[4] = {0x00};

    in_buff_definenvspace in_buff={0x00};
    out_buff_definenvspace out_buff={0x00};

    BYTE Tag[2]={0x00,0xc2};
    BYTE size[4]={0x00,0x00,0x00,0xf9};
    BYTE cmd[4]={0x00,0x00,0x80,0xcc};
    BYTE TagNV[2]={0x00,0x18};

    BYTE TagPCR[2]={0x00,0x06};
    BYTE resv[2]={0x01,0x01};
    BYTE sizeOfSelect[2]={0x00,0x02};
    BYTE pcrSelect[2]={0x00,0x01};

    BYTE PCR_data[DIGEST_LEN];
    BYTE index[4]={0x00,0x00,0x00,0x08};
    ret = TCM_PCRRead(index, PCR_data);
    if (ret == 0)
    {
        BYTE text[40];
        BYTE digest[DIGEST_LEN]={0x00};
        BYTE size1[4]={0x00,0x00,0x00,0x20};

        memcpy(text, sizeOfSelect, 2);
        memcpy(text+2, pcrSelect, 2);
        memcpy(text+4, size1, 4);
        memcpy(text+8, PCR_data, DIGEST_LEN);
        TCM_SM3_soft(text, 40, digest);

        memcpy(&in_buff.digestAtCreation1, digest, DIGEST_LEN);
        memcpy(&in_buff.digestAtRelease1, digest, DIGEST_LEN);
        memcpy(&in_buff.digestAtCreation2, digest, DIGEST_LEN);
        memcpy(&in_buff.digestAtRelease2, digest, DIGEST_LEN);
    } else {
        printf("PCR Read Error, ret=%d\n", ret);
        return ret;
    }

    BYTE TagNVAttribute[2]={0x00,0x17};
    BYTE NVPerm[4]={0x00,0x02,0x00,0x02};

    memcpy(&in_buff.TagNVAttribute, TagNVAttribute, 2);
    memcpy(&in_buff.NVpermission, NVPerm, 4);
    memcpy(&in_buff.nvSize, nvSize, 4);

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);

    memcpy(&in_buff.TagNV, TagNV, 2);
    memcpy(&in_buff.NVIndex, nvIndex, 4);

    memcpy(&in_buff.TagPCRinfo1, TagPCR, 2);
    memcpy(&in_buff.PCRresv1, resv, 2);
    memcpy(&in_buff.sizeOfSelect1, sizeOfSelect, 2);
    memcpy(&in_buff.pcrSelect1, pcrSelect, 2);
    memcpy(&in_buff.sizeOfSelect2, sizeOfSelect, 2);
    memcpy(&in_buff.pcrSelect2, pcrSelect, 2);

    memcpy(&in_buff.TagPCRinfo2, TagPCR, 2);
    memcpy(&in_buff.PCRresv2, resv, 2);
    memcpy(&in_buff.sizeOfSelect3, sizeOfSelect, 2);
    memcpy(&in_buff.pcrSelect3, pcrSelect, 2);
    memcpy(&in_buff.sizeOfSelect4, sizeOfSelect, 2);
    memcpy(&in_buff.pcrSelect4, pcrSelect, 2);

    BYTE entityType[2] = {0x00,0x02};
    BYTE entityValue[4] = {0x00};

    ret = TCM_APCreate(ownerAuth, entityType, entityValue, sessionHandle, seq_APCreateOut, session_key);
    if (ret)
    {
        printf("APCreate Failed, ret=%d\n", ret);
        return ret;
    }
    memcpy(&in_buff.sessionhandle, sessionHandle, 4);

    TCM_SM3_start();
    TCM_SM3_update(session_key, DIGEST_LEN);
    TCM_SM3_complete(seq_APCreateOut, 4, hmac_inMac);

    BYTE encAuth[DIGEST_LEN];
    for (i = 0; i < DIGEST_LEN; i++)
    {
        encAuth[i] = hmac_inMac[i] ^ 0x0;
    }
    memcpy(&in_buff.encAuth, encAuth, DIGEST_LEN);

    TCM_SM3_start();
    TCM_SM3_update((BYTE*)&in_buff.head.cmd, 4);
    TCM_SM3_update((BYTE*)&in_buff.TagNV, 171);
    TCM_SM3_complete(encAuth, DIGEST_LEN, hmac_inMac);

    memset(hmac_Text, 0x00, 64);
    memcpy(hmac_Text, hmac_inMac, DIGEST_LEN);
    memcpy(hmac_Text + DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(hmac_Text, 36, session_key, DIGEST_LEN, hmac_inMac);
    //end HMAC
    memcpy(&in_buff.HMAC, hmac_inMac, DIGEST_LEN);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_definenvspace), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff_definenvspace));
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if (ret != 0)
    {
        printf("TCM_NVDefineSpace Failed, ret=%d\n", ret);
        ErrorFlag = 1;
    } else {
        printf("%s, success\n", __func__);
    }

    ret = TCM_APTerminate(sessionHandle, seq_APCreateOut, session_key, !ErrorFlag);
    if (ret != 0)
    {
        printf("TCM_NV_APTerminate Error!, ret=%d\n", ret);
    } else {
        // printf("TCM_NV_APTerminate success\n");
    }

    return ret;
}

/* 将数据写入到自定义的nv空间，根据偏移量写入，nvsize为写入数据长度 */
static int TCM_NV_WriteValueAuth(BYTE ownerAuth[DIGEST_LEN], BYTE index[4], BYTE offset[4], BYTE nvSize[4], BYTE *buffer_Data)
{
    BYTE outBuffer[MAX_BUFSIZE];
    uint32_t outBufferLength=MAX_BUFSIZE;
    int ret = 0;
    int ErrorFlag = 0; // =1 seq not ++ ,=0 ,seq++
    
    unsigned char inMac[DIGEST_LEN] = {0x00};
    int value_offset = 0;
    int data_size = Unpack32(nvSize);

    //APCreate
    BYTE WriteValue[MAX_BUFSIZE] = {
        0x00,0xc2,      //(tag: TCM_TAG_RQU_AUTH1_COMMAND)
        0x00,0x00,0x00,0x5a,    //(paramSize: 90)
        0x00,0x00,0x80,0xcd,    //(ordinal: TCM_ORD_NV_WriteValue

        0x00,0x00,0x00,0x00,    //(nvIndex: 1)
        0x00,0x00,0x00,0x00,    //(offset: 0)

        0x00,0x00,0x00,0x20,    //data size:DIGEST_LEN
        //data(apk pub_key   len = DIGEST_LEN)
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  //数据长度不定，这里只是示意，写入的数据放在该位置

        0x00,0x00,0x00,0x00,    //(Session handle)会话句柄
        //HMAC
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  //总长度不定，与写入数据长度有关
    };
    value_offset = 10;
    memcpy(WriteValue + value_offset, index, 4);
    value_offset += 4;
    memcpy(WriteValue + value_offset, offset, 4);
    value_offset += 4;
    memcpy(WriteValue + value_offset, nvSize, 4);
    value_offset += 4;
    memcpy(WriteValue + value_offset, buffer_Data, data_size);
    value_offset += data_size;

    ///////////////////////////APCreate Begin//////////////////////////////////
    BYTE entityType[2] = {0x00,0x02};
    BYTE entityValue[4] = { 0x00 };
    BYTE hmac_Text[64] = { 0x00 };
    BYTE sessionHandle[4] = { 0x00 };
    BYTE seq_APCreateOut[4] = { 0x00 };
    BYTE session_key[DIGEST_LEN] = {0x00};

    ret = TCM_APCreate(ownerAuth, entityType, entityValue, sessionHandle, seq_APCreateOut, session_key);
    if (ret)
    {
        printf("TCM_APCreate Failed, ret=%d\n", ret);
        return ret;
    }

    //hash result
    BYTE hash_Result[DIGEST_LEN] = {0x00};
#if 1
    TCM_SM3_soft(WriteValue+6, 16+data_size, hash_Result);
#else
    TCM_SM3_start();
    TCM_SM3_update(WriteValue + 6, 16);
    TCM_SM3_complete(WriteValue + 22, data_size, hash_Result);
#endif
    //HMAC
    memcpy(hmac_Text, hash_Result, DIGEST_LEN);
    memcpy(hmac_Text+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(hmac_Text, 36, session_key, DIGEST_LEN, inMac);

    //NV_WriteValueAuth
    memcpy(WriteValue + value_offset, sessionHandle, 4);
    value_offset += 4;
    memcpy(WriteValue + value_offset, inMac, DIGEST_LEN);
    value_offset += DIGEST_LEN;
    Pack32(WriteValue + 2, value_offset);

    Tddli_TransmitData(WriteValue, value_offset, outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if (ret == 0)
    {
        printf("%s success\n", __func__);
    }
    else
    {
        ErrorFlag = 1;
        printf("%s Failed, ret=%d\n", __func__, ret);
    }

    ret = TCM_APTerminate(sessionHandle, seq_APCreateOut, session_key, !ErrorFlag);
    if (ret == 0)
    {
        // printf("TCM_APTerminate success!\n");
    }
    else
    {
        printf("TCM_APTerminate Error!, ret=%d\n", ret);
    }

    if (1 == ErrorFlag)
    {
        printf("%s failed\n", __func__);
        return -1;
    }
    return ret;
}

/* 根据偏移量从nv空间中读取数据，nvsize为读取的数据长度 */
static int TCM_NV_ReadValueAuth(BYTE ownerAuth[DIGEST_LEN], BYTE index[4], BYTE offset[4], BYTE nvSize[4], BYTE *buffer_Data)
{
    BYTE outBuffer[MAX_BUFSIZE]={0x00};
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret = 0;
    int ErrorFlag = 0; // =1 seq not ++ ,=0 ,seq++
    BYTE hmac_text[64] = { 0x00 };
    BYTE inMac[DIGEST_LEN] = { 0x00 };
    BYTE Tag[2]={0x00,0xc2};
    BYTE cmd[4]={0x00,0x00,0x80,0xcf};
    BYTE total_len[4]={0x00,0x00,0x00,0x3a};

    in_buff_NV_read in_buff;

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, total_len, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.nvIndex, index, 4);
    memcpy(&in_buff.offset, offset, 4);
    memcpy(&in_buff.data_len, nvSize, 4);

    /*-------------------------- APCreate Begin -----------------------*/
    BYTE entityType[2] = {0x00,0x02};
    BYTE entityValue[4] = { 0x00 };
    BYTE sessionHandle[4] = { 0x00 };
    BYTE seq_APCreateOut[4] = { 0x00 };
    BYTE session_key[DIGEST_LEN] = { 0x00 };

    ret = TCM_APCreate(ownerAuth, entityType, entityValue, sessionHandle, seq_APCreateOut, session_key);
    if (ret)
    {
        printf("TCM_APCreate Failed, ret=%d\n", ret);
        return ret;
    }

    //hash result
    BYTE hash_Result[DIGEST_LEN] = {0x00};
    TCM_SM3_soft((BYTE*)&in_buff.head.cmd, 16, hash_Result);

    //HMAC
    memset(hmac_text, 0x00, 64);
    memcpy(hmac_text, hash_Result, DIGEST_LEN);
    memcpy(hmac_text + DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(hmac_text, 36, session_key, DIGEST_LEN, inMac);

    memcpy(&in_buff.sessionhandle, sessionHandle, 4);
    memcpy(&in_buff.HMAC, inMac, DIGEST_LEN);

    Tddli_TransmitData((BYTE*)&in_buff, sizeof(in_buff), outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer +6);
    if (0 == ret)
    {
        // printf("%s, success\n", __func__);
        int length = Unpack32(outBuffer + 10);
        memcpy(buffer_Data, outBuffer + 14, length);
    }
    else
    {
        printf("%s Failed, ret=%d\n", __func__, ret);
        ErrorFlag = 1;
    }

    ret = TCM_APTerminate(sessionHandle, seq_APCreateOut, session_key, !ErrorFlag);
    if (ret == 0)
    {
        // printf("TCM_NV_APTerminate success\n");
    }
    else
    {
        printf("TCM_NV_APTerminate Failed, ret=%d\n", ret);
        ErrorFlag=1;
    }
    //end APTerminate

    if (ErrorFlag == 1)
    {
        printf("%s Failed\n", __func__);
        return -1;
    }
    return 0;
}

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE protocol[2];

    BYTE owner_data_len[4];
    BYTE enc_owner_data[129];
    BYTE smk_auth_len[4];
    BYTE smk_auth_data[129];

    BYTE smk_data[63];
    BYTE ap_handle[4];
    BYTE HMAC[32];
} in_buff_takeownership;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
    BYTE smk_data[63];
    BYTE inMac[32];
} out_buff_takeownership;

/* 创建授权密码，入参ownerAuth为授权码的sm3哈希值 */
int TCM_TakeOwnership(BYTE ownerAuth[DIGEST_LEN])
{   
    BYTE outBuffer[MAX_BUFSIZE]={0x00};
    uint32_t outBufferLength = MAX_BUFSIZE;
    uint32_t ret;
    BYTE inMac[DIGEST_LEN]={0x00};
    BYTE key[DIGEST_LEN] = {0x00};
    BYTE encOwnerAuth[129]={0x00};
    BYTE encSmkAuth[129]={0x00};
    BYTE callerNounce[DIGEST_LEN]={0x00};
    BYTE pubEK[65]={0x00};

    ret = TCM_ReadPubEK(pubEK);
    if (ret)
    {
        printf("tcm read pub ek failed\n");
        return ret;
    }
    tcmPrintf("pubEK", 65, pubEK);

    // 创建授权协议
    BYTE entityType[2]={0x00,0x12};
    BYTE entityValue[4] = {0x00};
    BYTE handle[4]={0x00};
    BYTE seq[4]={0x00};
    BYTE sessionkey[DIGEST_LEN]={0x00};

    ret = TCM_APCreate(key, entityType, entityValue, handle, seq, sessionkey);
    if (ret)
    {
        printf("TCM_APCreate Failed, ret=%d\n", ret);
        return ret;
    }

    //---------------------------------------------------------------
    //TakeOwnership
    in_buff_takeownership in_buff;
    out_buff_takeownership out_buff;

    BYTE AuthTag[2]={0x00,0xC2};
    BYTE size[4]={0x00,0x00,0x01,0x79};
    BYTE OwnerCmdCode[4]={0x00,0x00,0x80,0x0d};
    BYTE protocolID[2]={0x00,0x05};
    BYTE encOwnerAuthSize[4]={0x00,0x00,0x00,0x81};
    BYTE smkAuthSize[4]={0x00,0x00,0x00,0x81};

    memcpy(&in_buff.head.Tag, AuthTag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, OwnerCmdCode, 4);
    memcpy(&in_buff.protocol, protocolID, 2);

    memcpy(&in_buff.owner_data_len, encOwnerAuthSize, 4);
    TCM_encOwnerAuth(ownerAuth, pubEK, encOwnerAuth);
    memcpy(&in_buff.enc_owner_data, encOwnerAuth, 129);

    memcpy(&in_buff.smk_auth_len, smkAuthSize, 4);
    // 两次ecc加密结果不一样，但没关系，经过测试，使用同样的值会导致错误，错误码1
    TCM_encOwnerAuth(ownerAuth, pubEK, encSmkAuth);
    memcpy(&in_buff.smk_auth_data, encSmkAuth, 129);

    BYTE hash[DIGEST_LEN] = {0x00};
#if 1
    BYTE smk_buf[63] = {0x00};
    tcm_store_symkey store_symkey;
    tcm_smk_key_parms smk_parms;
    tcm_smk_key smk_key;

    Pack32((BYTE*)&store_symkey.resv1, 128);
    Pack32((BYTE*)&store_symkey.resv2, 128);
    Pack32((BYTE*)&store_symkey.size, 16);
    memset(&store_symkey.data, 0, 16);

    Pack32((BYTE*)&smk_parms.algorithmID, TCM_ALG_SMS4);
    Pack16((BYTE*)&smk_parms.encScheme, TCM_ES_SM4_CBC);
    Pack16((BYTE*)&smk_parms.sigScheme, TCM_SS_SM2NONE);
    Pack32((BYTE*)&smk_parms.parmSize, 28);
    smk_parms.store_symkey = store_symkey;

    Pack16((BYTE*)&smk_key.tag, TCM_TAG_KEY);
    Pack16((BYTE*)&smk_key.fill, 0);
    Pack16((BYTE*)&smk_key.key_usage, TCM_SM4KEY_STORAGE);
    Pack32((BYTE*)&smk_key.key_flags, TCM_isVolatile);
    smk_key.auth_data_usage = 0;

    smk_key.smk_key_parms = smk_parms;

    Pack32((BYTE*)&smk_key.PCRInfoSize, 0);
    smk_key.PCRInfo = NULL;

    memcpy(smk_buf, &smk_key, sizeof(smk_key));
#else
    //smk struct
    BYTE smk_buf[63]={
        0x00,0x15, 0x00,0x00, 0x00,0x18, 0x00,0x00,0x00,0x04, 0x00,

        0x00,0x00,0x00,0x0c,
        0x00,0x08,
        0x00,0x01,
        0x00,0x00,0x00,0x1c,
        0x00,0x00,0x00,0x80, 0x00,0x00,0x00,0x80, 
        0x00,0x00,0x00,0x10,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,

        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
#endif
    // tcmPrintf("smk_buf", sizeof(smk_key), smk_buf);

#if 0
    TCM_SM3_start();
    TCM_SM3_update(OwnerCmdCode, 4);
    TCM_SM3_update(protocolID, 2);
    TCM_SM3_update(encOwnerAuthSize, 4);
    TCM_SM3_update(encOwnerAuth, 129);
    TCM_SM3_update(smkAuthSize, 4);
    TCM_SM3_update(encSmkAuth, 129);
    TCM_SM3_complete(smk_buf, 63, hash);
#else
    BYTE data1[335]={0x00};
    memcpy(data1, OwnerCmdCode, 4);
    memcpy(data1 + 4, protocolID, 2);
    memcpy(data1 + 6, encOwnerAuthSize, 4);
    memcpy(data1 + 10, encOwnerAuth, 129);
    memcpy(data1 + 139, smkAuthSize, 4);
    memcpy(data1 + 143, encSmkAuth, 129);
    memcpy(data1 + 272, smk_buf, 63);
    TCM_SM3_soft(data1, 335, hash);
#endif

    BYTE buff[36] = {0x00};
    memcpy(buff, hash, DIGEST_LEN);
    memcpy(buff + DIGEST_LEN, seq, 4);
    tcm_hmac(buff, 36, ownerAuth, DIGEST_LEN, inMac);
    // tcmPrintf("inMac:", DIGEST_LEN, inMac);

    memcpy(&in_buff.smk_data, smk_buf, 63);
    memcpy(&in_buff.ap_handle, handle, 4);
    memcpy(&in_buff.HMAC, inMac, DIGEST_LEN);

    Tddli_TransmitData((BYTE*)&in_buff, sizeof(in_buff_takeownership), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff));
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if(ret == 0)
    {
        // printf("Command TakeOwnership success\n");
    }
    else
    {
        printf("Command TakeOwnership Failed, ret=%d\n", ret);
    }

    ret = TCM_APTerminate(handle, seq, key, 1);
    //Terminate end

    return ret;
}

/* 7.2.1 创建TCM硬件密钥 */
/*
in param:    ownerAuth    takeOwnerShip密钥的hash值
out param:   key_out      创建的密钥
*/
int TCM_CreateWrapKey(BYTE ownerAuth[DIGEST_LEN], BYTE key_out[248], BYTE pubkey[65])
{
    int ret=0;
    int in_buff_len=0;
    int outBufferLength=0;
    BYTE tag[2]={0x00,0xc2};
    BYTE data_len[4]={0x00};
    BYTE cmd[4]={0x00,0x00,0x80,0x1f};
    BYTE handle_SMK[4]={0x40,0x00,0x00,0x00};

    BYTE in_buffer[MAX_BUFSIZE]={0x00};
    BYTE out_buffer[MAX_BUFSIZE]={0x00};
#if 1
    BYTE tcm_sm2_key[39]={0x00};
    TCM_SM2_KEY sm2_keyinfo;
    TCM_SM2_KEY_PARMS sm2_parms;

    Pack32((BYTE*)&sm2_parms.algorithmID, TCM_ALG_ECC);  //TCM_ALG_ECC
    Pack16((BYTE*)&sm2_parms.encScheme, TCM_ES_SM2NONE); //TCM_ES_SM2NONE;  
    Pack16((BYTE*)&sm2_parms.sigScheme, TCM_SS_SM2); //TCM_SS_SM2; 
    Pack32((BYTE*)&sm2_parms.parmSize, 4);
    Pack32((BYTE*)&sm2_parms.keyLength, 256); //SM2 256 bit

    Pack16((BYTE*)&sm2_keyinfo.tag, TCM_TAG_KEY);   //TCM_TAG_KEY
    Pack16((BYTE*)&sm2_keyinfo.fill, 0);
    Pack16((BYTE*)&sm2_keyinfo.key_usage, TCM_SM2KEY_SIGNING); // 0x0010 For Sign,  must be TCM_SM2KEY_SIGNING
    Pack32((BYTE*)&sm2_keyinfo.key_flags, TCM_isVolatile);  //isvolatile, 易失性密钥
    sm2_keyinfo.auth_data_usage = TCM_AUTH_NEVER;
    sm2_keyinfo.sm2_parms = sm2_parms;
    Pack32((BYTE*)&sm2_keyinfo.PCRInfoSize, 0);
    sm2_keyinfo.PCRInfo = NULL;

    memcpy(tcm_sm2_key, &sm2_keyinfo, sizeof(sm2_keyinfo));
    // tcmPrintf("sm2_keyinfo", sizeof(sm2_keyinfo), (BYTE*)&sm2_keyinfo);
#else
    BYTE tcm_sm2_key[39]={
        0x00,0x15, 0x00,0x00, 0x00,0x10, 0x00,0x00,0x00,0x40, 0x00, 
        0x00,0x00,0x00,0x0b,  0x00,0x04, 0x00,0x05, 0x00,0x00,0x00,0x04, 0x00,0x00,0x01,0x00,
        0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
    };
#endif

    BYTE entityType[2]={0x00,0x01};
    BYTE entityValue[4]={0x40,0x00,0x00,0x00};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    ret = TCM_APCreate(ownerAuth, entityType, entityValue, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate failed, ret=%d\n", ret);
        return ret;
    }

    BYTE data1[36];
    BYTE hash[DIGEST_LEN];
    BYTE keyauth[DIGEST_LEN];

    memcpy(data1, sessionKey, DIGEST_LEN);
    memcpy(data1+DIGEST_LEN, seq_APCreateOut, 4);
    TCM_SM3_soft(data1, 36, hash);
    int i;
    for (i = 0; i < DIGEST_LEN; i++)
    {
        keyauth[i] = hash[i] ^ 0x00;
    }
    tcmPrintf("keyauth", DIGEST_LEN, keyauth);

    memcpy(in_buffer + in_buff_len, tag, 2);
    in_buff_len += 2;
    // 这里暂时不填入数据长度，最后计算填入
    // memcpy(in_buffer + in_buff_len, data_len, 4);
    in_buff_len += 4;
    memcpy(in_buffer + in_buff_len, cmd, 4);
    in_buff_len += 4;
    memcpy(in_buffer + in_buff_len, handle_SMK, 4);
    in_buff_len += 4;

    memcpy(in_buffer + in_buff_len, keyauth, DIGEST_LEN);
    in_buff_len += DIGEST_LEN;
    memcpy(in_buffer + in_buff_len, keyauth, DIGEST_LEN);
    in_buff_len += DIGEST_LEN;
    memcpy(in_buffer + in_buff_len, tcm_sm2_key, 39);
    in_buff_len += 39;
    memcpy(in_buffer + in_buff_len, handle_APCreateOut, 4);
    in_buff_len += 4;

    // printf("calculate hash begin\n");
#if 0
    TCM_SM3_start();
    TCM_SM3_update(cmd, 4);
    TCM_SM3_update(keyauth, DIGEST_LEN);
    TCM_SM3_update(keyauth, DIGEST_LEN);
    TCM_SM3_complete(tcm_key, sizeof(tcm_key), hash);
    tcmPrintf("hash", DIGEST_LEN, hash);
#else
    BYTE data[107];
    memcpy(data, cmd, 4);
    memcpy(data+4, keyauth,DIGEST_LEN);
    memcpy(data+36, keyauth,DIGEST_LEN);
    memcpy(data+68, tcm_sm2_key, 39);
    TCM_SM3_soft(data, 107, hash);
#endif

    BYTE content[36];
    BYTE inMac[DIGEST_LEN];

    memcpy(content, hash, DIGEST_LEN);
    memcpy(content+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(content, 36, sessionKey, DIGEST_LEN, inMac);
    tcmPrintf("inMac", DIGEST_LEN, inMac);

    memcpy(in_buffer + in_buff_len, inMac, DIGEST_LEN);
    in_buff_len += DIGEST_LEN;

    Pack32(data_len, in_buff_len);
    memcpy(in_buffer + 2, data_len, 4);

    Tddli_TransmitData(in_buffer, in_buff_len, out_buffer, &outBufferLength);
    out_buff_createwrapkey out_buff;
    memcpy(&out_buff, out_buffer, outBufferLength);
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if (ret != 0)
    {
        printf("tcm create wrap key failed, ret=%d\n", ret);
    }
    else
    {
        //创建密钥成功，将密钥信息返回，以供后续加载，TCM_LoadKey
        memcpy(key_out, out_buff.key_out, 248);
        uint32_t len=Unpack32(key_out+31);
        memcpy(pubkey, key_out+35, len);
        printf("TCM_CreateWrapKey success\n");
    }

    /* 即使上面步骤失败，这里也要释放AP会话，否则多次操作会报错（没有足够的空间加载秘钥） */
    ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 1);
    return ret;
}

/*  7.2.2
注意事项：不能频繁加载秘钥数据，否则会导致空间不足（错误码17），无法加载秘钥，并会引起字典攻击锁定（错误码2051）
在创建一次sm2密钥对后，将密钥句柄和公钥信息写入nv空间，再次签名时直接从nv读取

in param:   ownerAuth    takeOwnerShip密钥的hash值
            key          需要加载的密钥，从createwrapkey的返回值获得
            key_len  密钥长度
out param:  key_handle   秘钥句柄，获取公钥时需要
*/
int TCM_LoadKey(BYTE ownerAuth[DIGEST_LEN], BYTE key[256], uint32_t key_len, BYTE key_handle[4])
{
    int ret=0;
    int in_buff_len=0;
    int outBufferLength=0;
    BYTE inBuffer[MAX_BUFSIZE]={0x00};
    BYTE out_buffer[MAX_BUFSIZE]={0x00};
    BYTE tag[2]={0x00,0xc2};
    BYTE data_len[4]={0x00};
    BYTE cmd[4]={0x00,0x00,0x80,0xef};
    BYTE handle_SMK[4]={0x40,0x00,0x00,0x00};

    BYTE entityType[2]={0x00,0x04};
    BYTE entityValue[4]={0x40,0x00,0x00,0x00};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    ret = TCM_APCreate(ownerAuth, entityType, entityValue, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate failed, ret=%d\n", ret);
        return ret;
    }

    memcpy(inBuffer, tag, 2);
    in_buff_len += 2;

    // memcpy(inBuffer + in_buff_len, data_len, 4);
    in_buff_len += 4;

    memcpy(inBuffer + in_buff_len, cmd, 4);
    in_buff_len += 4;

    memcpy(inBuffer + in_buff_len, handle_SMK, 4);
    in_buff_len += 4;
    memcpy(inBuffer + in_buff_len, key, key_len);
    in_buff_len += key_len;
    memcpy(inBuffer + in_buff_len, handle_APCreateOut, 4);
    in_buff_len += 4;

    BYTE data[512]={0x00};
    BYTE hash[DIGEST_LEN]={0x00};

    memcpy(data, cmd, 4);
    memcpy(data+4, key, key_len);
    TCM_SM3_soft(data, key_len+4, hash);

    BYTE data1[36]={0x00};
    BYTE inMac[DIGEST_LEN];

    memcpy(data1, hash, DIGEST_LEN);
    memcpy(data1+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(data1, 36, sessionKey, DIGEST_LEN, inMac);
    tcmPrintf("inMac", DIGEST_LEN, inMac);

    memcpy(inBuffer + in_buff_len, inMac, DIGEST_LEN);
    in_buff_len += DIGEST_LEN;

    Pack32(data_len, in_buff_len);
    memcpy(inBuffer + 2, data_len, 4);

    Tddli_TransmitData(inBuffer, in_buff_len, out_buffer, &outBufferLength);
    out_buff_loadkey out_buff;
    memcpy(&out_buff, out_buffer, outBufferLength);
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if (ret != 0)
    {
        printf("tcm load key failed, ret=%d\n", ret);
    }
    else
    {
        //tcm load key success
        printf("TCM_LoadKey success\n");
        memcpy(key_handle, out_buff.handle, 4);
    }

    /* 即使上面步骤失败，这里也要释放AP会话，否则多次操作会报错（没有足够的空间加载秘钥） */
    ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 1);

    return ret;
}

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE key_handle[4];
    BYTE ap_handle[4];
    BYTE HMAC[DIGEST_LEN];
} in_buff_getpubkey;

int TCM_GetPubKey(BYTE ownerAuth[DIGEST_LEN], BYTE key_handle[4], BYTE pubkey[65])
{
    int ret=0;
    int outBufferLength=0;
    BYTE out_buffer[MAX_BUFSIZE]={0x00};
    in_buff_getpubkey in_buff;

    BYTE tag[2]={0x00,0xc2};
    BYTE data_len[4]={0x00,0x00,0x00,0x32};
    BYTE cmd[4]={0x00,0x00,0x80,0x21};

    BYTE entityType[2]={0x00,0x02};
    BYTE entityValue[4]={0x40,0x00,0x00,0x01};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    ret = TCM_APCreate(ownerAuth, entityType, entityValue, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate failed, ret=%d\n", ret);
        return ret;
    }

    memcpy(&in_buff.head.Tag, tag, 2);
    memcpy(&in_buff.head.total_len, data_len, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.key_handle, key_handle, 4);
    memcpy(&in_buff.ap_handle, handle_APCreateOut, 4);

    BYTE data[36];
    BYTE hash[DIGEST_LEN];
    BYTE HMAC[DIGEST_LEN];
    TCM_SM3_soft(cmd, 4, hash);

    memcpy(data, hash, DIGEST_LEN);
    memcpy(data + DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(data, 36, sessionKey, DIGEST_LEN, HMAC);

    memcpy(&in_buff.HMAC, HMAC, DIGEST_LEN);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_getpubkey), out_buffer, &outBufferLength);
    ret = Unpack32(out_buffer+6);
    if (ret)
    {
        printf("%s failed\n", __func__);
    }

    ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 1);

    return ret;
}

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE key_handle[4];
    BYTE about_key_handle[4];
    BYTE nonce[DIGEST_LEN];
} in_buff_certifykey;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
    BYTE certify_info[96];
    BYTE signed_len[4];
    BYTE signed_data[64];
} out_buff_certifykey;

int TCM_CertifyKey(BYTE key_handle[4], BYTE about_key_handle[4])
{
    int ret=0;
    in_buff_certifykey in_buff;
    out_buff_certifykey out_buff;
    BYTE out_buffer[MAX_BUFSIZE]={0x00};
    int outBufferLength=0;

    BYTE Tag[2]={0x00,0xc1};
    BYTE data_len[4]={0x00,0x00,0x00,0x32};
    BYTE cmd[4]={0x00,0x00,0x80,0x32};
    BYTE random_len[4]={0x00,0x00,0x00,0x20};
    BYTE nonce[DIGEST_LEN]={0x00};

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, data_len, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.key_handle, key_handle, 4);
    memcpy(&in_buff.about_key_handle, about_key_handle, 4);
    TCM_GetRandom(random_len, nonce);
    memcpy(&in_buff.nonce, nonce, DIGEST_LEN);

    Tddli_TransmitData((BYTE*)&in_buff, sizeof(in_buff), out_buffer, &outBufferLength);
    memcpy(&out_buff, out_buffer, sizeof(out_buff));
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    tcmPrintf("certify info", 96, out_buff.certify_info);
    tcmPrintf("signed_data", Unpack32(out_buff.signed_len), out_buff.signed_data);

    return ret;
}

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE smk_handle[4];
    BYTE keyauth[DIGEST_LEN];
    BYTE mkeyauth[DIGEST_LEN];
    BYTE keyinfo[146];
    BYTE handle[4];
    BYTE HMAC[DIGEST_LEN];
} in_buff_wrapkey;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
    BYTE keyinfo[159];
    BYTE inMac[DIGEST_LEN];
} out_buff_wrapkey;

/* 导入密钥（密钥已存在），这里由sm4专用
in param:  ownerAuth  用户授权码hash值
           sm4Key   需要导入的密钥
out param:  wrapKeyInfo   返回的密钥信息，后续需将该密钥信息加载到密钥树上（TCM_LoadKey）
 */
int TCM_WrapKey(BYTE ownerAuth[DIGEST_LEN], BYTE sm4Key[16], BYTE wrapKeyInfo[159])
{
    int ret=0;
    int outBufferLength=0;
    BYTE tag[2]={0x00,0xc2};
    BYTE data_len[4]={0x00};
    BYTE cmd[4]={0x00,0x00,0x80,0x1f};
    BYTE handle_SMK[4]={0x40,0x00,0x00,0x00};
    in_buff_wrapkey in_buff;
    out_buff_wrapkey out_buff;

    BYTE in_buffer[MAX_BUFSIZE]={0x00};
    BYTE out_buffer[MAX_BUFSIZE]={0x00};

    BYTE sm4Keyinfo[146] = {
        0x00,0x15,0x00,0x00,0x00,0x19,0x00,0x00, 0x00,0x00,0x00,
        0x00,0x00,0x00,0x0c,0x00,0x08,0x00,0x01, 0x00,0x00,0x00,0x1c,
        0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x80, 
        0x00,0x00,0x00,0x10,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x53,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x10,
        0x0a,0x0a,0x0a,0x0a,0x0a,0x0a, 0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a
    };
    memcpy(sm4Keyinfo + 130, sm4Key, 16);

    BYTE entityType[2]={0x00,0x04};
    BYTE entityValue[4]={0x00,0x00,0x00,0x00};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    ret = TCM_APCreate(ownerAuth, entityType, entityValue, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate failed, ret=%d\n", ret);
        return ret;
    }

//--------------------------------
    BYTE data1[36];
    BYTE hash[DIGEST_LEN];
    BYTE keyauth[DIGEST_LEN];

    memcpy(data1, sessionKey, DIGEST_LEN);
    memcpy(data1+DIGEST_LEN, seq_APCreateOut, 4);
    TCM_SM3_soft(data1, 36, hash);
    int i;
    for (i = 0; i < DIGEST_LEN; i++)
    {
        keyauth[i] = hash[i] ^ 0x00;
    }
    tcmPrintf("keyauth", DIGEST_LEN, keyauth);

    BYTE data2[214]={0x00};
    BYTE inMac[DIGEST_LEN]={0x00};
    memcpy(data2, cmd, 4);
    memcpy(data2+4, keyauth, DIGEST_LEN);
    memcpy(data2+36, keyauth, DIGEST_LEN);
    memcpy(data2+68, sm4Keyinfo, 146);
    TCM_SM3_soft(data2, 214, hash);

    memcpy(data1, hash, DIGEST_LEN);
    memcpy(data1+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(data1, 36, sessionKey, DIGEST_LEN, inMac);
//--------------------------------
    memcpy(&in_buff.head.Tag, tag, 2);
    Pack32(data_len, sizeof(in_buff));
    memcpy(&in_buff.head.total_len, data_len, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.smk_handle, handle_SMK, 4);
    memcpy(&in_buff.keyauth, keyauth, DIGEST_LEN);
    memcpy(&in_buff.mkeyauth, keyauth, DIGEST_LEN);
    memcpy(&in_buff.keyinfo, sm4Keyinfo, 146);
    memcpy(&in_buff.handle, handle_APCreateOut, 4);
    memcpy(&in_buff.HMAC, inMac, DIGEST_LEN);

    Tddli_TransmitData((BYTE*)&in_buff, sizeof(in_buff), out_buffer, &outBufferLength);
    memcpy(&out_buff, out_buffer, outBufferLength);
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if (ret != 0)
    {
        printf("tcm wrap key failed, ret=%d\n", ret);
    }
    else
    {
        //创建密钥成功，将密钥信息返回，以供后续加载，TCM_LoadKey
        memcpy(wrapKeyInfo, out_buff.keyinfo, 159);
        printf("TCM_WrapKey success\n");
    }

    /* 即使上面步骤失败，这里也要释放AP会话，否则多次操作会报错（没有足够的空间加载秘钥） */
    ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 1);
    return ret;
}

/*
sm4加密，加密数据长度最大为512
in param: key_handle   sm4密钥句柄，由tcm_loadkey返回获得
          IV  CBC模式下使用的向量，自行定义，长度16，解密向量应和加密向量一致
          data 待加密数据
          data_len 待加密数据长度，长度不为16的倍数时会用0补齐
out param: enc_data   加密后数据
           enc_data_len  加密后数据长度，总是为16的倍数
*/
int TCM_SM4Encrypt(BYTE key_handle[4], BYTE IV[16], 
    BYTE data[MAX_BUFSIZE], uint32_t data_len, 
    BYTE enc_data[MAX_BUFSIZE], uint32_t* enc_data_len)
{
    int ret=0;
    int in_buff_len=0;
    int outBufferLength=0;
    BYTE tag[2]={0x00,0xc2};
    BYTE input_len[4]={0x00};
    BYTE cmd[4]={0x00,0x00,0x80,0xc5};
    BYTE ownerAuth[DIGEST_LEN]={0x00};

    BYTE inBuffer[MAX_BUFSIZE]={0x00};
    BYTE out_buffer[MAX_BUFSIZE]={0x00};

    BYTE entityType[2]={0x00,0x01};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    ret = TCM_APCreate(ownerAuth, entityType, key_handle, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate failed, ret=%d\n", ret);
        return ret;
    }

    memcpy(inBuffer, tag, 2);
    in_buff_len += 2;
    in_buff_len += 4;
    memcpy(inBuffer+in_buff_len, cmd, 4);
    in_buff_len += 4;
    memcpy(inBuffer+in_buff_len, key_handle, 4);
    in_buff_len += 4;
    memcpy(inBuffer+in_buff_len, IV, 16);
    in_buff_len += 16;

    Pack32(input_len, data_len);
    memcpy(inBuffer+in_buff_len, input_len, 4);
    in_buff_len += 4;
    memcpy(inBuffer+in_buff_len, data, data_len);
    in_buff_len += data_len;
    memcpy(inBuffer+in_buff_len, handle_APCreateOut, 4);
    in_buff_len += 4;
//--------------------------------
    BYTE data1[MAX_BUFSIZE]={0x00};
    BYTE hash[DIGEST_LEN]={0x00};
    BYTE HMAC[DIGEST_LEN]={0x00};
    int data1_len=0;
    memcpy(data1, cmd, 4);
    data1_len += 4;
    memcpy(data1+data1_len, IV, 16);
    data1_len += 16;
    memcpy(data1+data1_len, input_len, 4);
    data1_len += 4;
    memcpy(data1+data1_len, data, data_len);
    data1_len += data_len;
    TCM_SM3_soft(data1, data1_len, hash);

    memset(data1, 0x00, sizeof(data1));
    memcpy(data1, hash, DIGEST_LEN);
    memcpy(data1+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(data1, 36, sessionKey, DIGEST_LEN, HMAC);
//--------------------------------
    memcpy(inBuffer+in_buff_len, HMAC, DIGEST_LEN);
    in_buff_len += DIGEST_LEN;
    Pack32(input_len, in_buff_len);
    memcpy(inBuffer+2, input_len, 4);

    Tddli_TransmitData(inBuffer, in_buff_len, out_buffer, &outBufferLength);
    ret = Unpack32(out_buffer+6);
    if (ret != 0)
    {
        printf("tcm sm4 encrypt failed, ret=%d\n", ret);
    }
    else
    {
        //sm4加密成功，将加密后数据返回
        *enc_data_len = Unpack32(out_buffer+10);
        memcpy(enc_data, out_buffer+14, *enc_data_len);
        printf("%s success\n", __func__);
    }

    /* 即使上面步骤失败，这里也要释放AP会话，否则多次操作会报错（没有足够的空间加载秘钥） */
    ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 1);
    return ret;
}

/*
sm4解密
in param: key_handle   sm4密钥句柄，由tcm_loadkey返回获得
          IV  CBC模式下使用的向量，自行定义，长度16，解密向量应和加密向量一致
          enc_data 待解密数据
          enc_data_len 待解密数据长度，长度不为16的倍数时会用0补齐
out param: data   解密后数据
           data_len  解密后数据长度，总是为16的倍数
*/
int TCM_SM4Decrypt(BYTE key_handle[4], BYTE IV[16],
    BYTE enc_data[MAX_BUFSIZE], uint32_t enc_data_len, 
    BYTE data[MAX_BUFSIZE], uint32_t* data_len)
{
    int ret=0;
    int in_buff_len=0;
    int outBufferLength=0;
    BYTE tag[2]={0x00,0xc2};
    BYTE input_len[4]={0x00};
    BYTE cmd[4]={0x00,0x00,0x80,0xc6};
    BYTE ownerAuth[DIGEST_LEN]={0x00};

    BYTE inBuffer[MAX_BUFSIZE]={0x00};
    BYTE out_buffer[MAX_BUFSIZE]={0x00};
    BYTE entityType[2]={0x00,0x01};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    ret = TCM_APCreate(ownerAuth, entityType, key_handle, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate failed, ret=%d\n", ret);
        return ret;
    }

    memcpy(inBuffer, tag, 2);
    in_buff_len += 2;
    in_buff_len += 4;
    memcpy(inBuffer+in_buff_len, cmd, 4);
    in_buff_len += 4;
    memcpy(inBuffer+in_buff_len, key_handle, 4);
    in_buff_len += 4;
    memcpy(inBuffer+in_buff_len, IV, 16);
    in_buff_len += 16;

    Pack32(input_len, enc_data_len);
    memcpy(inBuffer+in_buff_len, input_len, 4);
    in_buff_len += 4;
    memcpy(inBuffer+in_buff_len, enc_data, enc_data_len);
    in_buff_len += enc_data_len;
    memcpy(inBuffer+in_buff_len, handle_APCreateOut, 4);
    in_buff_len += 4;
//--------------------------------
    BYTE data1[MAX_BUFSIZE]={0x00};
    BYTE hash[DIGEST_LEN]={0x00};
    BYTE HMAC[DIGEST_LEN]={0x00};
    int data1_len=0;

    memcpy(data1, cmd, 4);
    data1_len += 4;
    memcpy(data1+data1_len, IV, 16);
    data1_len += 16;
    memcpy(data1+data1_len, input_len, 4);
    data1_len += 4;
    memcpy(data1+data1_len, enc_data, enc_data_len);
    data1_len += enc_data_len;
    TCM_SM3_soft(data1, data1_len, hash);

    memset(data1, 0x00, sizeof(data1));
    memcpy(data1, hash, DIGEST_LEN);
    memcpy(data1+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(data1, 36, sessionKey, DIGEST_LEN, HMAC);
//--------------------------------
    memcpy(inBuffer+in_buff_len, HMAC, DIGEST_LEN);
    in_buff_len += DIGEST_LEN;

    Pack32(input_len, in_buff_len);
    memcpy(inBuffer+2, input_len, 4);

    Tddli_TransmitData(inBuffer, in_buff_len, out_buffer, &outBufferLength);
    ret = Unpack32(out_buffer+6);
    if (ret != 0)
    {
        printf("%s failed, ret=%d\n", __func__, ret);
    }
    else
    {
        //sm4解密成功，将解密后数据返回
        *data_len = Unpack32(out_buffer+10);
        memcpy(data, out_buffer+14, *data_len);
        printf("%s success\n", __func__);
    }

    /* 即使上面步骤失败，这里也要释放AP会话，否则多次操作会报错（没有足够的空间加载秘钥） */
    ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 1);
    return ret;
}

typedef struct __attribute__((__packed__)) {
    send_data_head head;
    BYTE key_handle[4];
    BYTE dsg_len[4];
    BYTE dsg_data[DIGEST_LEN];
    BYTE handle[4];
    BYTE HMAC[DIGEST_LEN];
} in_buff_sign;

typedef struct __attribute__((__packed__)) {
    rsp_data_head head;
    BYTE signed_len[4];
    BYTE signed_data[64];
    BYTE inMac[DIGEST_LEN];
} out_buff_sign;

/*
sm2 sign，在可信芯片中采用私钥签名，返回签名后的数据，再使用tcm_ecc_verify和公钥来验签
in param:    key_handle  密钥句柄
             data    待签名数据的hash值，长度为DIGEST_LEN
out param:   signed_data   签名后的数据，长度为64
*/
int TCM_Sign(BYTE key_handle[4], BYTE data[DIGEST_LEN], BYTE signed_data[64])
{
    int ret=0;
    int in_buff_len=0;
    int outBufferLength=0;
    BYTE tag[2]={0x00,0xc2};
    BYTE input_len[4]={0x00};
    BYTE cmd[4]={0x00,0x00,0x80,0x3c};
    BYTE ownerAuth[DIGEST_LEN]={0x00};

    out_buff_sign out_buff;
    in_buff_sign in_buff;
    BYTE out_buffer[MAX_BUFSIZE]={0x00};

    BYTE entityType[2]={0x00,0x01};
    BYTE handle_APCreateOut[4]={0x00};
    BYTE seq_APCreateOut[4]={0x00};
    BYTE sessionKey[DIGEST_LEN]={0x00};

    ret = TCM_APCreate(ownerAuth, entityType, key_handle, handle_APCreateOut, seq_APCreateOut, sessionKey);
    if (ret)
    {
        printf("TCM_APCreate failed, ret=%d\n", ret);
        return ret;
    }

    Pack32(input_len, sizeof(in_buff_sign));
    memcpy(&in_buff.head.Tag, tag, 2);
    memcpy(&in_buff.head.total_len, input_len, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.key_handle, key_handle, 4);
    Pack32(input_len, DIGEST_LEN);
    memcpy(&in_buff.dsg_len, input_len, 4);
    memcpy(&in_buff.dsg_data, data, DIGEST_LEN);
//--------------------------------
    BYTE data2[40]={0x00};
    BYTE hash[DIGEST_LEN]={0x00};
    BYTE HMAC[DIGEST_LEN]={0x00};
    memcpy(data2, cmd, 4);
    memcpy(data2+4, input_len, 4);
    memcpy(data2+8, data, DIGEST_LEN);
    TCM_SM3_soft(data2, 40, hash);

    memcpy(data2, hash, DIGEST_LEN);
    memcpy(data2+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(data2, 36, sessionKey, DIGEST_LEN, HMAC);
//--------------------------------
    memcpy(&in_buff.handle, handle_APCreateOut, 4);
    memcpy(&in_buff.HMAC, HMAC, DIGEST_LEN);

    Tddli_TransmitData((BYTE*)&in_buff, sizeof(in_buff_sign), out_buffer, &outBufferLength);
    memcpy(&out_buff, out_buffer, outBufferLength);
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if (ret == 12)
    {
        printf("sm2 key invalid, you should reload it\n");
    }
    else if (ret == 0)
    {
        //sm2签名成功，将签名后数据返回
        memcpy(signed_data, out_buff.signed_data, 64);
        // printf("%s success\n", __func__);
    }
    else
    {
        printf("%s failed, ret=%d\n", __func__, ret);
    }

    /* 即使上面步骤失败，这里也要释放AP会话，否则多次操作会报错（没有足够的空间加载秘钥） */
    ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 1);

    return ret;
}

int TCM_write_sm2_keyhandle_nv(BYTE ownerAuth[DIGEST_LEN], BYTE offset[4], BYTE sm2_key[69])
{
    int ret=0;
    BYTE nvIndex[4]={0x00};
    BYTE nvSize[4]={0x00};

    Pack32(nvSize, 69);
    Pack32(nvIndex, TCM_NV_INDEX_SM2_KEY_HANDLE);
    ret = TCM_NV_WriteValueAuth(ownerAuth, nvIndex, offset, nvSize, sm2_key);

    return ret;
}

int TCM_read_sm2_keyhandle_nv(BYTE ownerAuth[DIGEST_LEN], BYTE offset[4], BYTE sm2_key[69])
{
    int ret=0;
    BYTE nvIndex[4]={0x00};
    BYTE nvSize[4]={0x00};

    Pack32(nvSize, 69);
    Pack32(nvIndex, TCM_NV_INDEX_SM2_KEY_HANDLE);
    ret = TCM_NV_ReadValueAuth(ownerAuth, nvIndex, offset, nvSize, sm2_key);

    return ret;
}

/* 新建sm2密钥对，并将密钥句柄和公钥写入nv */
int init_sm2_key(BYTE ownerAuth[DIGEST_LEN])
{
    int ret=0;
    BYTE pubkey[65]={0x00};
    BYTE key_out[248]={0x00};
    BYTE key_handle[4]={0x00};
    BYTE sm2_key[69]={0x00};

    ret = TCM_CreateWrapKey(ownerAuth, key_out, pubkey);
    if (ret == 0)
    {
        ret = TCM_LoadKey(ownerAuth, key_out, 248, key_handle);
        if (ret == 0)
        {
            BYTE offset[4]={0x00};

            memcpy(sm2_key, key_handle, 4);
            memcpy(sm2_key+4, pubkey, 65);

            ret = TCM_write_sm2_keyhandle_nv(ownerAuth, offset, sm2_key);
            if (ret != 0)
            {
                printf("write key handle to nv failed\n");
                return ret;
            }
        } else {
            printf("TCM_LoadKey failed\n");
        }
    } else {
        printf("TCM_CreateWrapKey failed\n");
    }

    return ret;
}

int TCM_write_sm4_keyhandle_nv(BYTE ownerAuth[DIGEST_LEN], BYTE offset[4], BYTE sm4_key[20])
{
    int ret=0;
    BYTE nvIndex[4]={0x00};
    BYTE nvSize[4]={0x00};

    Pack32(nvSize, 20);
    Pack32(nvIndex, TCM_NV_INDEX_SM4_KEY_HANDLE);
    ret = TCM_NV_WriteValueAuth(ownerAuth, nvIndex, offset, nvSize, sm4_key);

    return ret;
}

int TCM_read_sm4_keyhandle_nv(BYTE ownerAuth[DIGEST_LEN], BYTE offset[4], BYTE sm4_key[20])
{
    int ret=0;
    BYTE nvIndex[4]={0x00};
    BYTE nvSize[4]={0x00};

    Pack32(nvSize, 20);
    Pack32(nvIndex, TCM_NV_INDEX_SM4_KEY_HANDLE);
    ret = TCM_NV_ReadValueAuth(ownerAuth, nvIndex, offset, nvSize, sm4_key);

    return ret;
}

int write_sm4_key(BYTE ownerAuth[DIGEST_LEN], BYTE key[16])
{
    int ret=0;
    BYTE keyinfo[159]={0x00};
    BYTE handle[4]={0x00};
    BYTE sm4_key[20]={0x00};
    BYTE nvSize[4]={0x00};
    BYTE offset[4]={0x00};

    ret = TCM_WrapKey(ownerAuth, key, keyinfo);
    if (ret)
        return ret;

    ret = TCM_LoadKey(ownerAuth, keyinfo, 159, handle);
    if (ret)
        return ret;

    memcpy(sm4_key, handle, 4);
    memcpy(sm4_key+4, key, 16);

    Pack32(nvSize, 20);
    ret = TCM_write_sm4_keyhandle_nv(ownerAuth, offset, sm4_key);

    return ret;
}

/* 全流程签名，1、创建sm2密钥信息，取出公钥，2、加载sm2秘钥到芯片的密钥树，3、对数据的hash值实施签名 */
int TCM_Sign_full(BYTE ownerAuth[DIGEST_LEN], BYTE data[DIGEST_LEN], BYTE signed_data[64], BYTE pubkey[65])
{
    int ret=0;

    ret = init_sm2_key(ownerAuth);
    if (ret)
        return ret;

    BYTE sm2_key[69]={0x00};
    BYTE key_handle[4]={0xce, 0x08, 0xcc, 0xc2};
    BYTE offset[4]={0x00};

    ret = TCM_read_sm2_keyhandle_nv(ownerAuth, offset, sm2_key);
    if (ret)
        return ret;

    tcmPrintf("sm2 key", 69, sm2_key);
    memcpy(key_handle, sm2_key, 4);
    memcpy(pubkey, sm2_key+4, 65);

    ret = TCM_Sign(key_handle, data, signed_data);
    if (ret)
        printf("tcm sm2 sign failed\n");

    return ret;
}

int tcm_def_nv_tpcm(BYTE ownerAuth[DIGEST_LEN])
{
    int ret=0;
    BYTE nvIndex[4] = { 0x00 };
    BYTE attribute[4] = { 0x00 };
    Pack32(attribute, TCM_NV_PER_OWNER_READ | TCM_NV_PER_OWNERWRITE);
    tcmPrintf("TCM_NV_PER_OWNER_READ | TCM_NV_PER_OWNERWRITE", 4, attribute);

    int nvSizeTemp = 396;   // tcm策略文件固定大小，为396字节
    BYTE nvSize[4] = {0x00};

    Pack32(nvSize, nvSizeTemp);
    Pack32(nvIndex, TCM_NV_INDEX_TPCM_1);
    ret = TCM_NV_DefineSpace(ownerAuth, nvIndex, nvSize, attribute);
    if (0 == ret)
    {
        printf("TCM_NV_DefineSpace Success(TCM_NV_INDEX_TPCM_1)\n");
    }
    else
    {
        printf("TCM_NV_DefineSpace Failed(TCM_NV_INDEX_TPCM_1)\n");
        return ret;
    }

    nvSizeTemp = 48;
    Pack32(nvSize, nvSizeTemp);
    Pack32(nvIndex, TCM_NV_INDEX_TPCM_2);
    ret = TCM_NV_DefineSpace(ownerAuth, nvIndex, nvSize, attribute);
    if (0 == ret)
    {
        printf("TCM_NV_DefineSpace Success(TCM_NV_INDEX_TPCM_2)\n");
    }
    else
    {
        printf("TCM_NV_DefineSpace Failed(TCM_NV_INDEX_TPCM_2)\n");
    }

    return ret;
}

int tcm_write_file_tpcm(BYTE ownerAuth[DIGEST_LEN], char* filename)
{
    int ret=0;
    BYTE binData[1024]={0x00};
    uint32_t length=0;

    ret = read_File_data(filename, binData, &length);
    if (1 == ret)
    {
        printf("Read Policy File %s failed\n", filename);
        return ret;
    }

    BYTE nvIndex[4] = {0x00};
    Pack32(nvIndex, TCM_NV_INDEX_TPCM_1);
    BYTE offset[4] = {0x00};
    int size = 396;
    BYTE nvsize[4] = {0x00};
    Pack32(nvsize, size);

    ret = TCM_NV_WriteValueAuth(ownerAuth, nvIndex, offset, nvsize, binData);
    if (0 == ret)
    {
        printf("TCM_NV_WriteValueAuth Success\n");
    }
    else
    {
        printf("TCM_NV_WriteValueAuth Failed\n");
    }

    return ret;
}

int tcm_read_nv_tpcm(BYTE ownerAuth[DIGEST_LEN], BYTE data[396])
{
    int ret=0;
    BYTE nvIndex[4] = {0x00};
    Pack32(nvIndex, TCM_NV_INDEX_TPCM_1);
    BYTE offset[4] = {0x00};
    BYTE nvsize[4] = {0x00};
    Pack32(nvsize, 396);
    BYTE data1[396]={0x00};

    ret = TCM_NV_ReadValueAuth(ownerAuth, nvIndex, offset, nvsize, data);
    if (0 == ret)
    {
        printf("TCM_NV_ReadValueAuth(TCM_NV_INDEX_TPCM_1) Success\n");
        tcmPrintf("binData read:", 396, data);
    }
    else
    {
        printf("TCM_NV_ReadValueAuth(TCM_NV_INDEX_TPCM_1) Failed\n");
        return ret;
    }

    //tpcm2
    Pack32(nvIndex, TCM_NV_INDEX_TPCM_2);
    Pack32(nvsize, 48);
    ret = TCM_NV_ReadValueAuth(ownerAuth, nvIndex, offset, nvsize, data1);
    if (0 == ret)
    {
        printf("TCM_NV_ReadValueAuth(TCM_NV_INDEX_TPCM_2) Success\n");
    }
    else
    {        
        printf("TCM_NV_ReadValueAuth(TCM_NV_INDEX_TPCM_2) failed\n");
    }

    return ret;
}

int tcm_init(void)
{
    printf("------- tpcm init -------\n");
    int ret=0;

    ret = TCM_Startup();
    if (ret == 0 || ret == 0x26)
    {
        ;
    } else {
        printf("TCM Startup failed\n");
        return ret;
    }

    ret = TCM_SelfTestFull();
    if (ret != 0)
    {
        printf("TCM SelfTestFull failed\n");
        return ret;
    }

    ret = TCM_PhysicalEnable();
    if (ret)
    {
        printf("TCM_PhysicalEnable Failed\n");
        return ret;
    }

    ret = TCM_PhysicalSetActivated();
    if (ret)
    {
        printf("TCM_PhysicalSetActivated Failed\n");
        return ret;
    }

    return ret;
}

int TCM_device_init(void)
{
    int ret=0;
    BYTE ownerAuth[DIGEST_LEN]={0x00};
    ownerAuthInit(OWNER_PASSWD, ownerAuth);

    ret = tcm_init();
    if (ret)
    {
        return ret;
    }

    ret = TCM_TakeOwnership(ownerAuth);
    if (ret)
    {
        return ret;
    }

    /* 定义用于存放主动度量uboot信息的空间，长度为396 */
    ret = tcm_def_nv_tpcm(ownerAuth);
    if (ret)
    {
        return ret;
    }

    BYTE attribute[4]={0x00};
    Pack32(attribute, TCM_NV_PER_OWNER_READ | TCM_NV_PER_OWNERWRITE);
    BYTE nvSize[4] = {0x00,0x00,0x03,0xec};
    BYTE nvIndex[4]={0x00};

    Pack32(nvIndex, TCM_NV_INDEX_SM2_KEY_HANDLE);
    ret = TCM_NV_DefineSpace(ownerAuth, nvIndex, nvSize, attribute);
    if (ret)
    {
        return ret;
    }

    Pack32(nvIndex, TCM_NV_INDEX_SM4_KEY_HANDLE);
    ret = TCM_NV_DefineSpace(ownerAuth, nvIndex, nvSize, attribute);
    if (ret)
    {
        return ret;
    }

    /* 新建sm2密钥对，并将密钥句柄和公钥写入nv */
    ret = init_sm2_key(ownerAuth);
    if (ret)
    {
        return ret;
    }

    return ret;
}
