#ifndef __CRYPTO_API_H_
#define __CRYPTO_API_H_

#include "defines.h"
#include "err.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rand_drbg.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>

#define ARIA_BLOCK_SIZE 16 // 128bit



extern U2 sign_ECDSA(EC_KEY *ec_key, IN U1 *msg, IN U4 msg_len, OUT U1 *sign_R, OUT U1 *sign_S);
extern U2 verify_ECDSA(EC_KEY *ec_key, IN U1 *msg, IN U4 msg_len, IN U1 *sign_R, IN U1 *sign_S);
extern U2 Gen_EC_key(IN U4 std_curve, OUT EC_KEY **ec_key);

extern U2 sign_RSA_PSS(IN RSA *rsa_key, IN U1 *msg, IN U4 msg_len, OUT U1 *sign, OUT U4 *sign_len);
extern U2 verify_RSA_PSS(IN RSA *rsa_key, IN U1 *msg, IN U4 msg_len,  IN U1 *sign, IN U4 sign_len);

extern U2 encrypt_RSAES_OAEP(IN RSA *rsa_key, IN U1 *plain, IN U4 plain_len, OUT U1 * cipher, OUT U4 *cipher_len);
extern U2 decrypt_RSAES_OAEP(IN RSA *rsa_key, IN U1 *cipher, IN U4 cipher_len, OUT U1 *plain, OUT U4 *plain_len);

extern U2 GenRsaKey(IN U4 key_len, OUT RSA **rsa_key, OUT U1 *pub_key, OUT U1 *pri_key);
extern int GenKeyAriaAes(IN U1 key_idx, IN U4 key_len);
extern U2 EncryptKeyAriaCtr(IN U1 *kek, IN U1 *key, IN U4 key_len, OUT U1 *enc_key, OUT U4 *enc_key_len);
extern U2 DecryptKeyAriaCtr(IN U1 *kek, IN U1 *enc_key, IN U4 enc_key_len, OUT U1 *key, OUT U4 *key_len);
extern U2 GetKeyAriaAes(IN U1 key_idx, OUT U1 *key, OUT U4 *key_len);

extern U2 GenCtrDRBG(IN U4 req_rand_len, OUT U1 *out_rand);

extern U2 Sha256(IN U1 *msg, IN U4 msg_len, OUT U1 *md);
extern U2 HmacSha256(IN U1 *key, IN U4 key_len, IN U1 *msg, IN U4 msg_len, OUT U1 *md, OUT U4 *md_len);
extern U2 GmacGetTag(IN U1 *key, IN U1 *iv, IN U4 iv_len, IN U1 *aad, IN U4 aad_len, IN U4 req_tag_len, OUT U1 *tag, OUT U4 *tag_len);

extern U2 EncryptARIA(IN U1 key_idx, IN U1 padding_flag, IN U1 block_mode, IN U1 *plain_text, IN U4 plain_len, OUT U1 *cipher, OUT U4 *cipher_len, IN U1 req_tag_len, OUT U1 *tag, OUT U4 *tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad);

extern U2 DecryptARIA(IN U1 key_idx, IN U1 padding_flag, IN U1 block_mode, IN U1 *cipher_text, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len, IN U1 *tag, IN U1 tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad);
#endif
