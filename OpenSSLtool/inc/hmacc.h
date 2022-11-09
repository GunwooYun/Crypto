#ifndef __HMACC_H_
#define __HMACC_H_
#include "defines.h"

//extern HMAC_CTX *hmac_ctx;

extern U2 HMAC_init(IN U1 *key, IN U4 key_len);
extern U2 HMAC_update(IN U1 *data, IN U4 data_len);
extern U2 HMAC_final(OUT U1 *md, OUT U4 *md_len);
#endif
