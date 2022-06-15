#include "tpcm_util.h"
#include "ftdi_spi_tpm.h"
#include "tcm_hash.h"
#include "tcm_ecc.h"


/* 真随机数产生器 */
int TCM_GetRandom(BYTE data_len[4], BYTE random[1024])
{
    int iret=0;
    BYTE outBuffer[MAX_BUFSIZE];
    uint32_t outBufferLength = MAX_BUFSIZE;
    in_buff_random in_buff;
    out_buff_random out_buff;

    if (Unpack32(data_len) > 1024)
    {
        printf("random data size can NOT larger than 1024\n");
        return 1;
    }

    BYTE Tag[2]={0x00,0xc1};
    BYTE size[4]={0x00,0x00,0x00,0x0e};
    BYTE cmd[4]={0x00,0x00,0x80,0x46};

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.data_len, data_len, 4);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_random), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff_random));
    iret = reverse_bytes_uint32(out_buff.head.retcode);
    if (0 == iret)
    {
        // printf("cmd %s read success\n", __func__);
        memcpy(random, out_buff.random, Unpack32(out_buff.data_len));
    }
    else
    {
        printf("cmd get random failed, ret=%d\n", iret);
    }

    return iret;
}

/* 创建授权协议会话 */
int TCM_APCreate(BYTE ownerAuth[DIGEST_LEN], BYTE entityType[2], BYTE entityValue[4], 
    BYTE sessionHandle[4], BYTE seq_APCreateOut[4], BYTE sessionKey[DIGEST_LEN])
{
    in_buffer_apcreate in_buff;
    out_buff_apcreate out_buff;
    uint32_t outBufferLength;
    int ret=0;

    BYTE Tag[2]={0x00,0xc1};
    BYTE size_APCreate[4]={0x00,0x00,0x00,0x50};
    BYTE cmd_APCreate[4]={0x00,0x00,0x80,0xbf};
    BYTE data_len[4]={0x00,0x00,0x00,0x20};
    BYTE IncallerNonce[DIGEST_LEN];
    BYTE outBuffer[MAX_BUFSIZE];

    printf("\n-------> begin %s\n", __func__);
    TCM_GetRandom(data_len, IncallerNonce);

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, size_APCreate, 4);
    memcpy(&in_buff.head.cmd, cmd_APCreate, 4);
    memcpy(&in_buff.entityType, entityType, 2);
    memcpy(&in_buff.entityValue, entityValue, 4);
    memcpy(&in_buff.nonce, IncallerNonce, DIGEST_LEN);

    BYTE hmac_Text[36]={0x00};
    BYTE inMac[DIGEST_LEN]={0x00};

    memcpy(hmac_Text, cmd_APCreate, 4);
    memcpy(hmac_Text+4, IncallerNonce, DIGEST_LEN);
    tcm_hmac(hmac_Text, 36, ownerAuth, DIGEST_LEN, inMac);

    memcpy(&in_buff.inMac, inMac, DIGEST_LEN);

    Tddli_TransmitData((char *)&in_buff, sizeof(in_buffer_apcreate), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff_apcreate));
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if (ret != 0)
    {
        printf("%s failed, ret=%d\n", __func__, ret);
    }
    else
    {
        memcpy(sessionHandle, out_buff.ap_handle, 4);
        memcpy(seq_APCreateOut, out_buff.seq, 4);

        memcpy(hmac_Text, IncallerNonce, DIGEST_LEN);
        memcpy(hmac_Text + DIGEST_LEN, out_buff.tcm_nonce, DIGEST_LEN);
        tcm_hmac(hmac_Text, 64, ownerAuth, DIGEST_LEN, sessionKey);
    }

    return ret;
}

/* 销毁授权协议会话，flag为1，seq++，flag为0，seq为原值 */
int TCM_APTerminate(BYTE handle[4], BYTE seq[4], BYTE sessionKey[DIGEST_LEN], uint8_t flag)
{
    in_buff_apterminate in_buff;
    out_buff_apterminate out_buff;
    BYTE inMac[DIGEST_LEN]={0x00};
    int ret=0;
    BYTE outBuffer[MAX_BUFSIZE]={0x00};
    uint32_t outBufferLength;

    BYTE Tag_Terminate[2]={0x00,0xc2};
    BYTE Size_Terminate[4]={0x00,0x00,0x00,0x2e};
    BYTE CommandCode_Terminate[4]={0x00,0x00,0x80,0xc0};

    printf("\n-------> begin %s\n", __func__);
    memcpy(&in_buff.head.Tag, Tag_Terminate, 2);
    memcpy(&in_buff.head.total_len, Size_Terminate, 4);
    memcpy(&in_buff.head.cmd, CommandCode_Terminate, 4);
    memcpy(&in_buff.ap_handle, handle, 4);

    BYTE hashTerminate[DIGEST_LEN]={0x00};
    TCM_SM3_soft(CommandCode_Terminate, 4, hashTerminate);

    BYTE buff[36]={0x00};
    memcpy(buff, hashTerminate, DIGEST_LEN);
    if (flag == 1)
    {
        BYTE seq1[4]={0x00};
        int temp = Unpack32(seq) + 1;
        Pack32(seq1, temp);
        memcpy(buff+DIGEST_LEN, seq1, 4);
    }
    else
    {
        memcpy(buff+DIGEST_LEN, seq, 4);
    }
    tcm_hmac(buff, 36, sessionKey, DIGEST_LEN, inMac);

    memcpy(&in_buff.inMac, inMac, DIGEST_LEN);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_apterminate), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff_apterminate));
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if (ret != 0)
    {
        printf("%s failed, ret=%d\n", __func__, ret);
    } else {
        // printf("%s success\n", __func__);
    }

    return ret;
}

//获取tpcm固件版本
int TCM_GetVersion(void)
{
    BYTE outBuffer[4096];
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;
    tcm_version version;
    BYTE cmdGetVersion[18] = {0x00,0xC1, 0x00,0x00,0x00,0x12, 0x00,0x00,0x80,0x65, 0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x00};

    Tddli_TransmitData(cmdGetVersion, sizeof(cmdGetVersion), outBuffer, &outBufferLength);

    memcpy(&version, outBuffer, sizeof(tcm_version));
    TCM_version_t ver;
    memcpy(&ver, &version.version, 4);
    printf("tpcm chip version=%02x.%02x\n", ver.major, ver.minor);

    ret = reverse_bytes_uint32(version.head.retcode);
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

/* 根据用户输入的授权码计算出相应sm3哈希值 */
void ownerAuthInit(char *a, BYTE *ownerAuth)
{
    unsigned int len = 0;
    BYTE b[DIGEST_LEN] = {0x00};
    memset(b, 0x00, DIGEST_LEN);

    StringToHex(a, b, &len);
    //password with sm3 for DIGEST_LEN BYTE auth
    BYTE hashResult[DIGEST_LEN] = { 0x00 };

    // tcmPrintf("passwd:", len, b);

    // 获取授权值的哈希值
    int ret = TCM_SM3_soft(b, len, hashResult);
    if (0 != ret)
    {
        printf("SM3 hash error\n");
        return;
    }
    memcpy(ownerAuth, hashResult, DIGEST_LEN);
    // tcmPrintf("hash:", DIGEST_LEN, hashResult);
}

/* 通过出厂内置的公钥pubEK将明文ownerAuth加密成encOwnerAuth */
int TCM_encOwnerAuth(BYTE ownerAuth[DIGEST_LEN], BYTE pubEK[65], BYTE encOwnerAuth[129])
{
    uint32_t ret;
    int iret = 0;
    unsigned int encOwnerAuthSize=256;

    memset(encOwnerAuth, 0, 129);

    tcm_ecc_init();
    ret = tcm_ecc_encrypt((unsigned char*)ownerAuth, DIGEST_LEN,
                        pubEK, 65,
                        encOwnerAuth, &encOwnerAuthSize);
    tcm_ecc_release();
    if (ret == 0)
    {
        tcmPrintf("encOwnerAuth:", encOwnerAuthSize, encOwnerAuth);
        // printf("tcm_ecc_encrypt owner success\n");
    }
    else
    {
        printf("tcm_ecc_encrypt owner error, ret=%d\n", ret);
    }

    return ret;
}

//--------------------在TPCM芯片上实现SM3功能----------------------------
int TCM_SM3_start(void)
{
    BYTE outBuffer[MAX_BUFSIZE];
    memset(outBuffer, 0x00, MAX_BUFSIZE);
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;

    BYTE    SM3Start[] = {0x00,0xC1, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x80,0xea};

    Tddli_TransmitData(SM3Start, sizeof(SM3Start), outBuffer, &outBufferLength);
    // outBufferLength = Unpack32(outBuffer+2);
    ret = Unpack32(outBuffer+6);
    if(ret == 0)
    {
        // printf("%s Success\n", __func__);
    }
    else
    {
        printf("%s Error code:%d\n", __func__, ret);
    }

    return ret;
}

int TCM_SM3_update(BYTE* content, size_t length)
{
    BYTE outBuffer[MAX_BUFSIZE]={0x00};
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret=0;
    BYTE sm3_data[MAX_BUFSIZE]={0};
    BYTE len[4]={0x00};
    int total_len=0;
    BYTE data_len[4]={0x00};

    BYTE Tag[2] = {0x00,0xC1};
    memcpy(sm3_data+total_len, Tag, 2);
    total_len += 2;

    // 先略过总长度，最后计算
    total_len += 4;

    BYTE cmd[4] = {0x00,0x00,0x80,0xeb};
    memcpy(sm3_data+total_len, cmd, 4);
    total_len += 4;

    Pack32(data_len, length);
    memcpy(sm3_data+total_len, data_len, 4);
    total_len += 4;

    memcpy(sm3_data + total_len, content, length);
    total_len += length;

    Pack32(len, total_len);
    memcpy(sm3_data+2, len, 4);

    Tddli_TransmitData(sm3_data, total_len, outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer+6);
    if(ret==0)
    {
        // printf("%s Success\n", __func__);
    }
    else
    {
        printf("%s Error code:%d\n", __func__, ret);
    }

    return ret;
}

int TCM_SM3_complete(BYTE* content, size_t length, BYTE digest[32])
{
    BYTE outBuffer[MAX_BUFSIZE]={0x00};
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;
    BYTE data[4] = {0x00};
    BYTE sm3_data[512]={0};
    size_t total_len = 14+length;

    BYTE Tag[2] = {0x00,0xC1};
    memcpy(sm3_data, Tag, 2);

    Pack32(data, total_len);
    memcpy(sm3_data+2, data, 4);

    BYTE cmd[4] = {0x00,0x00,0x80,0xec};
    memcpy(sm3_data+6, cmd, 4);

    Pack32(data, length);
    memcpy(sm3_data+10, data, 4);
    memcpy(sm3_data+14, content, length);

    Tddli_TransmitData(sm3_data, total_len, outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer+6);
    if(ret==0)
    {
        // printf("%s Success\n", __func__);
        memcpy(digest, outBuffer+10, 32);
    }
    else
    {
        printf("%s Error code:%d\n", __func__, ret);
    }

    return ret;
}

/* 完成当前sm3会话并将结果值扩展到指定的PCR中 */
int TCM_SM3_completeExtend(BYTE* content, uint32_t length, BYTE PCR_index[4], 
    BYTE digest[DIGEST_LEN], BYTE PCR_result[DIGEST_LEN])
{
    BYTE outBuffer[MAX_BUFSIZE]={0x00};
    uint32_t outBufferLength = MAX_BUFSIZE;
    int ret;
    BYTE len[4] = {0x00};
    BYTE sm3_data[MAX_BUFSIZE]={0};
    size_t total_len = 18+length;

    BYTE Tag[2] = {0x00,0xC1};
    memcpy(sm3_data, Tag, 2);

    Pack32(len, total_len);
    memcpy(sm3_data+2, len, 4);

    BYTE cmd[4] = {0x00,0x00,0x80,0xed};
    memcpy(sm3_data+6, cmd, 4);

    Pack32(len, length);
    memcpy(sm3_data+10, PCR_index, 4);
    memcpy(sm3_data+14, len, 4);
    memcpy(sm3_data+18, content, length);

    Tddli_TransmitData(sm3_data, total_len, outBuffer, &outBufferLength);
    ret = Unpack32(outBuffer+6);
    if(ret == 0)
    {
        // printf("%s Success\n", __func__);
        memcpy(digest, outBuffer+10, DIGEST_LEN);
        memcpy(PCR_result, outBuffer+42, DIGEST_LEN);
    }
    else
    {
        printf("%s Error code:%d\n", __func__, ret);
    }

    return ret;
}

/* 6.1.3.2 授权读密码模块密钥公钥，验证所有者的密码 */
int TCM_OwnerReadInternalPub(BYTE ownerAuth[DIGEST_LEN], BYTE ekPubData[65])
{
    in_buff_readinpub in_buff;
    out_buff_readinpub out_buff;
    BYTE outBuffer[MAX_BUFSIZE];
    uint32_t outBufferLength;
    int ret=0;
    BYTE inMac[DIGEST_LEN]={0x00};
    BYTE hmac_Text[128]={0x00};
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

    //OwnerReadPubEK
    BYTE AuthTag[2]={0x00,0xC2};
    BYTE size_OwnerReadPubEK[4]={0x00,0x00,0x00,0x32};
    BYTE cmdOwnerReadPubEK[4]={0x00,0x00,0x80,0x81};      //TCM_ORD_OwnerReadPubek
    BYTE handle_EK[4]={0x40,0x00,0x00,0x06};

    //6.hmac
    BYTE hashResult[DIGEST_LEN] = {0x00};
    BYTE text[8];

    memcpy(text, cmdOwnerReadPubEK, 4);
    memcpy(text+4, handle_EK, 4);
    TCM_SM3_soft(text, 8, hashResult);

    memcpy(hmac_Text, hashResult, DIGEST_LEN);
    memcpy(hmac_Text+DIGEST_LEN, seq_APCreateOut, 4);
    tcm_hmac(hmac_Text, 36, sessionKey, DIGEST_LEN, inMac);

    memcpy(&in_buff.head.Tag, AuthTag, 2);
    memcpy(&in_buff.head.total_len, size_OwnerReadPubEK, 4);
    memcpy(&in_buff.head.cmd, cmdOwnerReadPubEK, 4);
    memcpy(&in_buff.ek_handle, handle_EK, 4);
    memcpy(&in_buff.ap_handle, handle_APCreateOut, 4);
    memcpy(&in_buff.inMac, inMac, DIGEST_LEN);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_readinpub), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff_readinpub));
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if (ret != 0)
    {
        printf("%s failed, ret=%d\n", __func__, ret);
        return ret;
    } else {
        memcpy(ekPubData, out_buff.ekPubData, Unpack32(out_buff.ekpubdata_len));
    }

    ret = TCM_APTerminate(handle_APCreateOut, seq_APCreateOut, sessionKey, 1);

    return ret;
}

/* 6.1.3.1 读取出厂内置在芯片内部的sm2非对称密钥的公钥信息 */
int TCM_ReadPubEK(BYTE ekPubData[65])
{
    uint32_t ret;
    in_buff_readpubek in_buff;
    out_buff_readpubek out_buff;
    uint32_t outBufferLength = MAX_BUFSIZE;
    BYTE outBuffer[MAX_BUFSIZE];
    BYTE Tag[2]={0x00,0xc1};
    BYTE total_len[4]={0x00,0x00,0x00,0x2a};
    BYTE cmd[4]={0x00,0x00,0x80,0x7c};

    // 经过测试，抗重放参数可以为任意值，但不能短时间内多次使用同样的抗重放参数
    BYTE nonce_size[4]={0x00,0x00,0x00,0x20};
    BYTE nonce[DIGEST_LEN]={0x00};
    TCM_GetRandom(nonce_size, nonce);

    memcpy(&in_buff.head.Tag, Tag, 2);
    memcpy(&in_buff.head.total_len, total_len, 4);
    memcpy(&in_buff.head.cmd, cmd, 4);
    memcpy(&in_buff.nonce, nonce, DIGEST_LEN);

    Tddli_TransmitData((char*)&in_buff, sizeof(in_buff_readpubek), outBuffer, &outBufferLength);
    memcpy(&out_buff, outBuffer, sizeof(out_buff_readinpub));
    ret = reverse_bytes_uint32(out_buff.head.retcode);
    if(ret == 0)
    {
        // printf("Command %s success\n", __func__);
        memcpy(ekPubData, out_buff.ekPubData, Unpack32(out_buff.ekpubdata_len));
    }
    else
    {
        printf("%s Failed, ret=%d\n", __func__, ret);
        return ret;
    }

    return ret;
}
