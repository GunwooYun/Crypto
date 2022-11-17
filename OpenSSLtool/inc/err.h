#ifndef _ERR_H_
#define _ERR_H_
#include <openssl/err.h>
#include "defines.h"

void DebugPrintLine(void);
void DebugPrintArr(IN U1 *arr, IN U4 arr_len);
void HandleErrors(void);

#endif
