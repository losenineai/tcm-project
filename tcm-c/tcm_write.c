/*
  该程序主要用于设备触发GPIO来自动烧录信息到TPCM模块NV空间
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>

#include "tcm_hash.h"
#include "common.h"
#include "tpcm_func.h"
#include "ftdi_spi_tpm.h"
#include "tcm_ecc.h"
#include "tpcm_util.h"

extern int g_iDisplayFlag;   //=0,display,    =1,not dispaly
#define SPI_BUS_FREQ     10000000

static int write_tcm_policy(char *spidev, char* policy_file)
{
    int ret = 0;
    g_iDisplayFlag = 1;

    if (access(policy_file, F_OK) != 0)
        return -1;

    ret = FtdiSpiInit(SPI_BUS_FREQ, 0, spidev);
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

    //仅启动tpcm，不新建nv空间
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

    BYTE ownerAuth[DIGEST_LEN]={0x00};
    ownerAuthInit(OWNER_PASSWD, ownerAuth);
    ret = tcm_write_file_tpcm(ownerAuth, policy_file);
    return ret;
}

static void initGpio(int n)
{
    char gpio_path[64];
    sprintf(gpio_path, "/sys/class/gpio/gpio%d", n);

    if (access(gpio_path, F_OK) != 0)
    {
        FILE * fp = fopen("/sys/class/gpio/export", "w");
        if (fp == NULL)
            printf("export open %d filed\n", n);
        else
            fprintf(fp,"%d", n);

        fclose(fp);
    }
}

static void setGpioDirection(int n,char *direction)
{
    char path[64] = {0};

    sprintf(path,"/sys/class/gpio/gpio%d/direction", n);
    FILE * fp =fopen(path,"w");
    if (fp == NULL)
        printf("direction open filed, %d\n", n);
    else
        fprintf(fp,"%s", direction);

    fclose(fp);
}

static int getGpioValue(int n)
{
    char path[64];
    char value_str[3];
    int fd;

    sprintf(path, "/sys/class/gpio/gpio%d/value", n);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("Failed to open gpio %d value for reading!", n);
        return -1;
    }

    if (read(fd, value_str, 3) < 0) {
        printf("Failed to read %d value!", n);
        return -1;
    }

    close(fd);
    return (atoi(value_str));
}

static int setGpioValue(int n, int value)
{
    char path[64];
    char value_str[3];
    int fd;

    sprintf(value_str, "%d", value);

    sprintf(path, "/sys/class/gpio/gpio%d/value", n);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        printf("Failed to open gpio value for reading!");
        return -1;
    }

    if (write(fd, value_str, 3) < 0) {
        printf("Failed to read %d value!", n);
        return -1;
    }

    close(fd);
    return 0;
}

int main(int argc, char **argv) 
{
    int ret = 0;
    int c;
    char spidev[16];
    char policy_file[128];
#if 1
    while((c = getopt(argc, argv, "d:f:")) != -1)
    {
        switch(c)
        {
        case 'd':
        {
            strcpy(spidev, optarg);
            break;
        }
        case 'f':
        {
            strcpy(policy_file, optarg);
            break;
        }
        default:
            break;
        }
    }
#else
    strcpy(spidev, "/dev/spidev1.0");
    strcpy(policy_file, "/root/policy.bin");
#endif

#if 1
    initGpio(201);
    initGpio(163);
    setGpioDirection(201, "in");
    setGpioDirection(163, "out");
    
    while(1)
    {
        if (getGpioValue(201))
        {
            ret = write_tcm_policy(spidev, policy_file);
            if (ret == 0)
            {
                //烧写成功，滴一声
                printf("write success\n");
                setGpioValue(163, 1);
                sleep(1);
                setGpioValue(163, 0);
            }
            else
            {
                //烧写失败，滴10秒
                printf("write Failed\n");
                setGpioValue(163, 1);
                sleep(10);
                setGpioValue(163, 0);
            }
        }
        usleep(1);
    }
#else
    //不用gpio操作，直接写策略文件
    ret = write_tcm_policy(spidev, policy_file);
#endif
    return 0;
}
