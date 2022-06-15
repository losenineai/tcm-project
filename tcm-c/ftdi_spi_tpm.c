#include <endian.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>

#include "ftdi_spi_tpm.h"


static unsigned locality_;   // Set at initialization.
static int debug_level;

int spi_cs0_fd;				//file descriptor for the SPI device
int spi_cs1_fd;				//file descriptor for the SPI device
unsigned char spi_mode;
unsigned char spi_bitsPerWord;
unsigned int spi_speed;
extern int g_iDisplayFlag;

/**
* SPI OPEN PORT 
*/
//spi_device    0=CS0, 1=CS1
static int SpiOpenPort(uint32_t freq, int spi_device, char* spi_name)
{
    int status_value = -1;
    int *spi_cs_fd;

    //----- SET SPI MODE -----
    //SPI_MODE_0 (0,0)  CPOL = 0, CPHA = 0, Clock idle low, data is clocked in on rising edge, output data (change) on falling edge
    //SPI_MODE_1 (0,1)  CPOL = 0, CPHA = 1, Clock idle low, data is clocked in on falling edge, output data (change) on rising edge
    //SPI_MODE_2 (1,0)  CPOL = 1, CPHA = 0, Clock idle high, data is clocked in on falling edge, output data (change) on rising edge
    //SPI_MODE_3 (1,1)  CPOL = 1, CPHA = 1, Clock idle high, data is clocked in on rising, edge output data (change) on falling edge
    spi_mode = SPI_MODE_0;

    //----- SET BITS PER WORD -----
    spi_bitsPerWord = 8;

    // 需要根据不同设备的SPI总线速率设定，
    // 比如 orangepi zero2的SPI总线速率为65MHZ，
    // orangepi one plus的SPI总线速率为65MHZ，
    // 龙芯板的总线速率为25MHZ
    //----- SET SPI BUS SPEED -----
    spi_speed = freq;       //1000000 = 1MHz (1uS per bit) 

    if (spi_device)
        spi_cs_fd = &spi_cs1_fd;
    else
        spi_cs_fd = &spi_cs0_fd;

    if (spi_device)
        *spi_cs_fd = open(spi_name, O_RDWR);
    else
        *spi_cs_fd = open(spi_name, O_RDWR);
    if (*spi_cs_fd < 0)
    {
        perror("Error - Could not open SPI device");
        exit(1);
    }

    status_value = ioctl(*spi_cs_fd, SPI_IOC_WR_MODE, &spi_mode);
    if(status_value < 0)
    {
        perror("Could not set SPIMode (WR)...ioctl fail");
        exit(1);
    }

    status_value = ioctl(*spi_cs_fd, SPI_IOC_RD_MODE, &spi_mode);
    if(status_value < 0)
    {
        perror("Could not set SPIMode (RD)...ioctl fail");
        exit(1);
    }

    status_value = ioctl(*spi_cs_fd, SPI_IOC_WR_BITS_PER_WORD, &spi_bitsPerWord);
    if(status_value < 0)
    {
        perror("Could not set SPI bitsPerWord (WR)...ioctl fail");
        exit(1);
    }

    status_value = ioctl(*spi_cs_fd, SPI_IOC_RD_BITS_PER_WORD, &spi_bitsPerWord);
    if(status_value < 0)
    {
        perror("Could not set SPI bitsPerWord(RD)...ioctl fail");
        exit(1);
    }

    status_value = ioctl(*spi_cs_fd, SPI_IOC_WR_MAX_SPEED_HZ, &spi_speed);
    if(status_value < 0)
    {
        perror("Could not set SPI speed (WR)...ioctl fail");
        exit(1);
    }

    status_value = ioctl(*spi_cs_fd, SPI_IOC_RD_MAX_SPEED_HZ, &spi_speed);
    if(status_value < 0)
    {
        perror("Could not set SPI speed (RD)...ioctl fail");
        exit(1);
    }

    return status_value;
}

/**
* SPI CLOSE PORT 
*/
int SpiClosePort(int spi_device)
{
    int status_value = -1;
    int *spi_cs_fd;

    if (spi_device)
        spi_cs_fd = &spi_cs1_fd;
    else
        spi_cs_fd = &spi_cs0_fd;

    status_value = close(*spi_cs_fd);
    if(status_value < 0)
    {
        perror("Error - Could not close SPI device");
        exit(1);
    }
    return status_value;
}

void FtdiStop(void) 
{
    SpiClosePort(0);
}

static void trace_dump(const char *prefix, unsigned reg, size_t bytes, const uint8_t *buffer)
{
    static char prev_prefix;
    static unsigned prev_reg;
    static int current_line;

    if (!debug_level)
        return;

    if ((debug_level < 2) && (reg != TPM_DATA_FIFO_REG))
        return;

    if ((prev_prefix != *prefix) || (prev_reg != reg)) {
        prev_prefix = *prefix;
        prev_reg = reg;
        printf("\n%s %2.2x:", prefix, reg);
        current_line = 0;
    }

    if ((reg != TPM_DATA_FIFO_REG) && (bytes == 4)) {
        printf(" %8.8x", *(const uint32_t*) buffer);
    } else {
        int i;

        for (i = 0; i < bytes; i++) {
            if (current_line && !(current_line % BYTES_PER_LINE)) {
                printf("\n");
                current_line = 0;
            }
            current_line++;
            printf(" %2.2x", buffer[i]);
        }
    }
}

/**
* SPI WRITE & READ DATA 
*/
//data      Bytes to write.  Contents is overwritten with bytes read.
static int SpiWriteAndRead(int spi_device, unsigned char *data, int length)
{
    struct spi_ioc_transfer spi[length];
    int i = 0;
    int retVal = -1;
    int *spi_cs_fd;

    if (spi_device)
        spi_cs_fd = &spi_cs1_fd;
    else
        spi_cs_fd = &spi_cs0_fd;

    for (i = 0; i < length; i++)
    {
        memset(&spi[i], 0, sizeof (spi[i]));
        spi[i].tx_buf = (unsigned long)(data + i); // transmit from "data"
        spi[i].rx_buf = (unsigned long)(data + i); // receive into "data"
        spi[i].len    = sizeof(*(data + i));
    }

    retVal = ioctl(*spi_cs_fd, SPI_IOC_MESSAGE(length), &spi);
    if(retVal < 0)
    {
        perror("Error - Problem transmitting spi data..ioctl");
        exit(1);
    }

    return retVal;
}

static int FtdiWriteReg(unsigned reg_number, size_t bytes, const void *buffer)
{
    int *spi_cs_fd;
    spi_cs_fd = &spi_cs0_fd;
    usleep(100);
    unsigned char *value; 
    SpiFrameHeader header;
    int i;

    header.body[0] = (false ? 0x80 : 0) | 0x40 | (bytes - 1);
    for (i = 0; i < 3; i++)
        header.body[i + 1] = (reg_number >> (8 * (2 - i))) & 0xff;

    value = malloc(bytes + 4);
    for (i = 0; i < 4; i++)
        value[i] = header.body[i];
    memcpy(value + 4, buffer, bytes);

    SpiWriteAndRead(0, value, bytes + 4);

    trace_dump("W", reg_number, bytes, buffer);
    free(value);

    return true;
}

static int FtdiReadReg(unsigned reg_number, size_t bytes, void *buffer)
{
    int *spi_cs_fd;
    spi_cs_fd = &spi_cs0_fd;
    usleep(100);
    unsigned char *value;  
    SpiFrameHeader header;
    int i;

    header.body[0] = (true ? 0x80 : 0) | 0x40 | (bytes - 1);
    for (i = 0; i < 3; i++)
        header.body[i + 1] = (reg_number >> (8 * (2 - i))) & 0xff;

    value = malloc(bytes + 4);
    for (i = 0; i < 4; i++)
        value[i] = header.body[i];

    for (i = 4; i < bytes + 4; i++)
        value[i] = 0x00;

    SpiWriteAndRead(0, value, bytes + 4);

    if (buffer)
        memcpy(buffer, value + 4, bytes);
    free(value);

    trace_dump("R", reg_number, bytes, buffer);

    return true;
}

static int ReadTpmSts(uint32_t *status)
{
    return FtdiReadReg(TPM_STS_REG, sizeof(*status), status);
}

static int WriteTpmSts(uint32_t status)
{
    return FtdiWriteReg(TPM_STS_REG, sizeof(status), &status);
}

static uint32_t GetBurstCount(void)
{
    uint32_t status;

    ReadTpmSts(&status);
    return (status >> burstCountShift) & burstCountMask;
}

int FtdiSpiInit(uint32_t freq, int enable_debug, char* spi_name)
{
    uint32_t did_vid;
    uint8_t rid;
    uint16_t vid;
    debug_level = enable_debug;

    SpiOpenPort(freq, 0, spi_name);
    FtdiReadReg(TPM_DID_VID_REG, sizeof(did_vid), &did_vid);
    // printf("TPM_DID_VID_REG=%x\n", TPM_DID_VID_REG);
    // printf("TPM_RID_REG=%x\n",  TPM_RID_REG);

    vid = did_vid & 0xffff;
    if ((vid != 0x15d1) && (vid != 0x1ae0) && (vid != 0x1b4e) && (vid != 0x1050)) {
        fprintf(stderr, "unknown did_vid: %#x\n", did_vid);
        return false;
    }

    FtdiReadReg(TPM_RID_REG, sizeof(rid), &rid);

    printf("\nConnected to device vid:did:rid of %4.4x: %4.4x: %2.2x\n",
           did_vid & 0xffff, did_vid >> 16, rid);

    return true;
}

static int WaitForStatus(uint32_t statusMask, uint32_t statusExpected)
{
    uint32_t status;
    uint32_t iCount=0;
    time_t target_time;
    static unsigned max_timeout;

    target_time = time(NULL) + MAX_STATUS_TIMEOUT;
    do {
        usleep(10);
        iCount++;

        if (time(NULL) >= target_time) {
            fprintf(stderr, "failed to get expected status %x\n", statusExpected);
            return false;
        }

        ReadTpmSts(&status);
    } while ((status & statusMask) != statusExpected);

    return true;
}

static void SpinSpinner(void)
{
    static const char *spinner = "\\|/-";
    static int index;

    if (index > strlen(spinner))
        index = 0;

    /* 8 is the code for 'cursor left' */
    fprintf(stdout, "%c%c", 8, spinner[index++]);
    fflush(stdout);
}

/* tpm_command points at a buffer 4096 bytes in size */
/* 返回0失败，返回1成功 */
static int FtdiSendCommandAndWait(const uint8_t *tpm_command, const int command_size, uint8_t* result, int* result_len)
{
    uint32_t status;
    uint32_t expected_status_bits;
    size_t handled_so_far=0;
    uint32_t payload_size;
    uint8_t cmd;
    char message[1024];
    int offset = 0;
    uint8_t result_tpm[204800]={0};

    // Try claiming locality zero.
    FtdiReadReg(TPM_ACCESS_REG, sizeof(cmd), &cmd);

    if ((cmd & (activeLocality & tpmRegValidSts)) == (activeLocality & tpmRegValidSts)) {
        /*
        * Locality active - maybe reset line is not connected?
        * Release the locality and try again
        */
        cmd = activeLocality;

        FtdiWriteReg(TPM_ACCESS_REG, sizeof(cmd), &cmd);
        FtdiReadReg(TPM_ACCESS_REG, sizeof(cmd), &cmd);
    }
    // tpmEstablishment can be either set or not.
    if ((cmd & ~(tpmEstablishment | activeLocality)) != tpmRegValidSts) {
        fprintf(stderr, "invalid reset status: %#x\n", cmd);
        return 0;
    }
    cmd = requestUse;

    FtdiWriteReg(TPM_ACCESS_REG, sizeof(cmd), &cmd);
    FtdiReadReg(TPM_ACCESS_REG, sizeof(cmd), &cmd);

    if ((cmd &  ~tpmEstablishment) != (tpmRegValidSts | activeLocality)) {
        fprintf(stderr, "failed to claim locality, status: %#x\n", cmd);
        return 0;
    }

    WriteTpmSts(commandReady);

    expected_status_bits = commandReady;
    if (!WaitForStatus(expected_status_bits, expected_status_bits)) {
        printf("Failed processing. %s:\n", message);
        return 0;
    } else {
        // printf("%d, success to processing. %s\n", __LINE__, message);
    }

    memcpy(&payload_size, tpm_command + 2, sizeof(payload_size));
    payload_size = be32toh(payload_size);
    offset += snprintf(message, sizeof(message), "Message size %d", payload_size);

    // No need to wait for the sts.Expect bit to be set, at least with the
    // 15d1:001b device, let's just write the command into FIFO, make sure not
    // to exceed the burst count.
    /* 写入tpm command到data fifo中 */
    do {
        uint32_t transaction_size;
        uint32_t burst_count = GetBurstCount();

        if (burst_count > 64)
            burst_count = 64;

        transaction_size = command_size - handled_so_far;
        if (transaction_size > burst_count)
            transaction_size = burst_count;

        if (transaction_size) {
            FtdiWriteReg(TPM_DATA_FIFO_REG, transaction_size, tpm_command + handled_so_far);
            handled_so_far += transaction_size;
        }
    } while(handled_so_far != command_size);

    /* 等待状态信息 */
    expected_status_bits = stsValid;
    if (!WaitForStatus(expected_status_bits, expected_status_bits)) {
        printf("%d, Failed processing. %s:\n", __LINE__, message);
        return 0;
    } else {
        // printf("%d, success to processing. %s\n", __LINE__, message);
    }

    // And tell the device it can start processing it.
    WriteTpmSts(tpmGo);
    expected_status_bits = stsValid | dataAvail;

    if (!WaitForStatus(expected_status_bits, expected_status_bits)) {
        printf("%d, Failed processing. %s:\n", __LINE__, message);
        return 0;
    } else {
        // printf("%d, success to processing. %s\n", __LINE__, message);
    }

    // The tpm_command is ready, let's read it.
    // First we read the FIFO payload header, to see how much data to expect.
    // The header size is fixed to six bytes, the total payload size is stored
    // in network order in the last four bytes of the header.
    // Let's read the header first.
    FtdiReadReg(TPM_DATA_FIFO_REG, HEADER_SIZE, result_tpm);
    handled_so_far = HEADER_SIZE;

    // Figure out the total payload size.
    memcpy(&payload_size, result_tpm + 2, sizeof(payload_size));
    payload_size = be32toh(payload_size);

    if (!debug_level)
        SpinSpinner();

    if (payload_size > MAX_RESPONSE_SIZE)
        return 0;

    // Let's read all but the last byte in the FIFO to make sure the status
    // register is showing correct flow control bits: 'more data' until the last
    // byte and then 'no more data' once the last byte is read.
    payload_size = payload_size - 1;
    do {
        uint32_t transaction_size;
        uint32_t burst_count = GetBurstCount();

        //printf("1.burst_count:%d\n",burst_count);
        if (burst_count > 64)
            burst_count = 64;

        transaction_size = payload_size - handled_so_far;
        if (transaction_size > burst_count)
            transaction_size = burst_count;

        if (transaction_size) {
            FtdiReadReg(TPM_DATA_FIFO_REG, transaction_size, result_tpm + handled_so_far);

            handled_so_far += transaction_size;
        }
    } while(handled_so_far != payload_size);

    // Verify that there is still data to come.
    ReadTpmSts(&status);
    if ((status & expected_status_bits) != expected_status_bits) {
        fprintf(stderr, "unexpected status %#x\n", status);
        return 0;
    }

    FtdiReadReg(TPM_DATA_FIFO_REG, 32, result_tpm + handled_so_far);

    tcmPrintf("\ninput data:", command_size, tpm_command);
    tcmPrintf("output data:", handled_so_far+1, result_tpm);

    if (result != NULL)
        memcpy(result, result_tpm, handled_so_far+1);
    if (result_len != NULL)
        *result_len = handled_so_far + 1;

    // Verify that 'data available' is not asseretd any more.
    ReadTpmSts(&status);
    if ((status & expected_status_bits) != stsValid) {
        fprintf(stderr, "unexpected status %#x\n", status);
        return 0;
    }

    /* Move the TPM back to idle state. */
    WriteTpmSts(commandReady);
    ReadTpmSts(&status);

    return 1;
}

void Tddli_TransmitData(char* inBuffer, int inBuffer_size, char* outBuffer, int *outBuffer_size)
{
    // 返回1，正常，返回0，异常
    if (FtdiSendCommandAndWait(inBuffer, inBuffer_size, outBuffer, outBuffer_size) == 1)
    {
        // printf("%s, success\n", __func__);
        return;
    }
    else
    {
        printf("%s, failed\n", __func__);
        return;
    }
}
