#ifndef __ARIA_H_
#define __ARIA_H_

#include "defines.h"

// extern EVP_CIPHER_CTX *ctx;
// extern EVP_CIPHER_CTX *evp_ctx_dec;


// extern U1 cipher_type[12];

//extern U2 ARIA_Enc_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv);
extern U2 ARIA_Enc_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv, IN U2 add_len, IN U1 *aad);
//extern U2 ARIA_Enc_Update(IN U1 padding_flag, IN U1 *plain_text, IN U4 plain_len,  OUT U1 *cipher, OUT U4 *cipher_len);
extern U2 ARIA_Enc_Update(IN U1 padding_flag, IN U1 block_mode, IN U1 *plain_text, IN U4 plain_len,  OUT U1 *cipher, OUT U4 *cipher_len, IN U1 req_tag_len, OUT U1 *tag, OUT U4 *tag_len);
//extern U2 ARIA_Dec_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv);
extern U2 ARIA_Dec_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad);
//extern U2 ARIA_Dec_Update(IN U1 padding_flag, IN U1 *cipher_text, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len);
extern U2 ARIA_Dec_Update(IN U1 padding_flag, IN U1 *cipher_text, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len, IN U1 *tag, IN U1 tag_len);

extern U2 EncryptARIA(IN U1 *key, IN U1 padding_flag, IN U1 block_mode, IN U1 *plain_text, IN U4 plain_len, OUT U1 *cipher, OUT U4 *cipher_len, IN U1 req_tag_len, OUT U1 *tag, OUT U4 *tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad);

extern U2 DecryptARIA(IN U1 *key, IN U1 padding_flag, IN U1 block_mode, IN U1 *cipher_text, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len, IN U1 *tag, IN U1 tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad);
#endif
