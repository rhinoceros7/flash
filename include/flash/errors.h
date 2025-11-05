#ifndef FLASH_ERRORS_H
#define FLASH_ERRORS_H

typedef enum {
    FLASH_OK = 0,
    FLASH_EOF = 1,
    FLASH_EIO = -1,
    FLASH_EBADMAGIC = -2,
    FLASH_ETRUNC_HDR = -3,
    FLASH_ETRUNC_PAYLOAD = -4,
    FLASH_EBUFSIZE = -5,
    FLASH_ECRC = -6,
    FLASH_ECHAIN = -7
  } flash_status_t;

#endif // FLASH_ERRORS_H