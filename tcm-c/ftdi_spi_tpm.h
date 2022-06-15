#ifndef _FTDI_SPI_H_
#define _FTDI_SPI_H_

#include "common.h"

typedef enum {
    false = 0,
    true,
} bool;

/* This is in seconds. */
#define MAX_STATUS_TIMEOUT 120

#define MAX_RESPONSE_SIZE 2220
#define HEADER_SIZE 6

#define BYTES_PER_LINE 24

// Assorted TPM2 registers for interface type FIFO.
#define TPM_REG_BASE	0xd40000

#define TPM_ACCESS_REG      (TPM_REG_BASE + locality_ * 0x1000 + 0x0)
#define TPM_STS_REG         (TPM_REG_BASE + locality_ * 0x1000 + 0x18)
#define TPM_DATA_FIFO_REG   (TPM_REG_BASE + locality_ * 0x1000 + 0x24)
#define TPM_DID_VID_REG     (TPM_REG_BASE + locality_ * 0x1000 + 0xf00)
#define TPM_RID_REG         (TPM_REG_BASE + locality_ * 0x1000 + 0xf04)
#define TPM_INTERFACE_ID    (TPM_REG_BASE + locality_ * 0x1000 + 0x30)

// Locality management bits (in TPM_ACCESS_REG)
enum TpmAccessBits {
    tpmRegValidSts = (1 << 7),
    activeLocality = (1 << 5),
    requestUse = (1 << 1),
    tpmEstablishment = (1 << 0),
};

enum TpmStsBits {
    tpmFamilyShift = 26,
    tpmFamilyMask = ((1 << 2) - 1),  // 2 bits wide
    tpmFamilyTPM2 = 1,
    resetEstablishmentBit = (1 << 25),
    commandCancel = (1 << 24),
    burstCountShift = 8,
    burstCountMask = ((1 << 16) -1),  // 16 bits wide
    stsValid = (1 << 7),
    commandReady = (1 << 6),
    tpmGo = (1 << 5),
    dataAvail = (1 << 4),
    Expect = (1 << 3),
    selfTestDone = (1 << 2),
    responseRetry = (1 << 1),
};

// SPI frame header for TPM transactions is 4 bytes in size, it is described
// in section "6.4.6 Spi Bit Protocol" of the TCG issued "TPM Profile (PTP)
// Specification Revision 00.43.
typedef struct {
    unsigned char body[4];
} SpiFrameHeader;


int FtdiSpiInit(uint32_t freq, int enable_debug, char* spi_name);
void FtdiStop(void);
void Tddli_TransmitData(char* inBuffer, int inBuffer_size, char* outBuffer, int *outBuffer_size);

#endif
