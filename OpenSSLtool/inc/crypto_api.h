#ifndef __CRYPTO_API_H_
#define __CRYPTO_API_H_

#include "defines.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rand_drbg.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "err.h"
#define ARIA_BLOCK_SIZE 16 // 128bit

extern U2 GenKey(IN U4 key_len, OUT U1 *key);

extern U2 GenCtrDRBG(IN U4 req_rand_len, OUT U1 *out_rand);

extern U2 Sha256(IN U1 *msg, IN U4 msg_len, OUT U1 *md);
extern U2 HmacSha256(IN U1 *key, IN U4 key_len, IN U1 *msg, IN U4 msg_len, OUT U1 *md, OUT U4 *md_len);

extern U2 EncryptARIA(IN U1 *key, IN U1 padding_flag, IN U1 block_mode, IN U1 *plain_text, IN U4 plain_len, OUT U1 *cipher, OUT U4 *cipher_len, IN U1 req_tag_len, OUT U1 *tag, OUT U4 *tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad);

extern U2 DecryptARIA(IN U1 *key, IN U1 padding_flag, IN U1 block_mode, IN U1 *cipher_text, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len, IN U1 *tag, IN U1 tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad);
#endif
