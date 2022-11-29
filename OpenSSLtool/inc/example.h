#ifndef __INTERFACE_H_
#define __INTERFACE_H_

#include "crypto_api.h"
#include "defines.h"
#include "err.h"

void testGmac(void);
void testDrbg(void);
void testRSA_sign_verify(void);
void testRSA_enc_dec(void);
void testSha256(void);
void testEcdsa(void);
void testAria(void);
void testhmac(void);
#endif
