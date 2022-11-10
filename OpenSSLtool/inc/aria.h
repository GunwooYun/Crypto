#ifndef __ARIA_H_
#define __ARIA_H_

#include "defines.h"

extern U2 ARIA_Enc_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv);
extern U2 ARIA_Enc_Update(IN U1 padding_flag, IN U1 *plain_text, IN U4 plain_len,  OUT U1 *cipher, OUT U4 *cipher_len);
extern U2 ARIA_Dec_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv);
extern U2 ARIA_Dec_Update(IN U1 padding_flag, IN U1 *cipher_text, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len);

#endif