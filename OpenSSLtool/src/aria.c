#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "../inc/aria.h"
#include "../inc/defines.h"

EVP_CIPHER_CTX *evp_ctx_enc = NULL;
EVP_CIPHER_CTX *evp_ctx_dec = NULL;


U1 cipher_type[12];

U2 ARIA_Enc_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv)
{
    U4 key_len = 16;
    U2 ret = 0x0000;

    memset(cipher_type, 0, 12);

    switch(block_mode)
    {
        case MODE_ECB :
            sprintf(cipher_type, "aria-%d-ecb", key_len*8);
            break;
        case MODE_CBC :
            sprintf(cipher_type, "aria-%d-cbc", key_len*8);
            break;
        case MODE_CTR :
            sprintf(cipher_type, "aria-%d-ctr", key_len*8);
            break;
        case MODE_GCM :
            sprintf(cipher_type, "aria-%d-gcm", key_len*8);
            break;
        default :
            break;
    }

    const EVP_CIPHER *evp_cipher_enc = EVP_get_cipherbyname(cipher_type);
    evp_ctx_enc = EVP_CIPHER_CTX_new();

    if((evp_cipher_enc == NULL) || (evp_ctx_enc == NULL))
    {
        printf("evp_cipher_enc OR evp_ctx_enc is NULL\n");
        return 0xffff;
    }

    /* Encryption INIT */
    ret = EVP_EncryptInit(evp_ctx_enc, evp_cipher_enc, key, iv);
    if(!ret)
    {
        printf("EVP_EncryptInit_ex ERROR\n");
        return 0xffff;
    }
    return 0x9000;
}

U2 ARIA_Enc_Update(IN U1 padding_flag, IN U1 *plain_text, IN U4 plain_len,  OUT U1 *cipher, OUT U4 *cipher_len)
{
    U2 ret = 0x0000;
    U4 outl = 0;
    U1 *cipher_buf = NULL;
    U4 cipher_buf_len = 0;
    int nBytesWritten = 0;

    ret = EVP_CIPHER_CTX_set_padding(evp_ctx_enc, padding_flag);
    if(!ret)
    {
        printf("EVP_CIPHER_CTX_set_padding ERROR\n");
        return 0xffff;
    }

    cipher_buf_len = plain_len + EVP_CIPHER_CTX_block_size(evp_ctx_enc);

    cipher_buf = (U1 *)malloc(cipher_buf_len);
    if(cipher_buf == NULL)
    {
        printf("cipher buf malloc failed\n");
        return 0xffff;
    }

    EVP_EncryptUpdate(evp_ctx_enc, &cipher_buf[outl], &nBytesWritten, plain_text, plain_len);
    outl += nBytesWritten;

    EVP_EncryptFinal(evp_ctx_enc, &cipher_buf[outl], &nBytesWritten);
    outl += nBytesWritten;

    //cipher = cipher_buf;
    memcpy(cipher, cipher_buf, outl);
    *cipher_len = outl;


    /*
    for(int i = 0; i < outl; i++)
        printf("%#x ", cipher_buf[i]);
        */

    EVP_CIPHER_CTX_free(evp_ctx_enc);
    free(cipher_buf);

    return 0x9000;
}

U2 ARIA_Dec_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv)
{
    U4 key_len = 16;
    //U1 cipher_type[12] = {0x00, };
    U2 ret = 0x0000;

    memset(cipher_type, 0, 12);

    switch(block_mode)
    {
        case MODE_ECB :
            sprintf(cipher_type, "aria-%d-ecb", key_len*8);
            break;
        case MODE_CBC :
            sprintf(cipher_type, "aria-%d-cbc", key_len*8);
            break;
        case MODE_CTR :
            sprintf(cipher_type, "aria-%d-ctr", key_len*8);
            break;
        case MODE_GCM :
            sprintf(cipher_type, "aria-%d-gcm", key_len*8);
            break;
        default :
            break;
    }

    const EVP_CIPHER *evp_cipher_dec = EVP_get_cipherbyname(cipher_type);
    evp_ctx_dec = EVP_CIPHER_CTX_new();

    if((evp_cipher_dec == NULL) || (evp_ctx_dec == NULL))
    {
        printf("evp_cipher_dec OR evp_ctx_dec is NULL\n");
        return 0xffff;
    }

    /* Encryption INIT */
    ret = EVP_DecryptInit(evp_ctx_dec, evp_cipher_dec, key, iv);
    if(!ret)
    {
        printf("EVP_DecryptInit_ex ERROR\n");
        return 0xffff;
    }
    return 0x9000;
}

U2 ARIA_Dec_Update(IN U1 padding_flag, IN U1 *cipher_text, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len)
{
    U2 ret = 0;
    U4 outl = 0;
    U4 plain_buf_len = 0;
    int nBytesWritten = 0;
    ret = EVP_CIPHER_CTX_set_padding(evp_ctx_dec, padding_flag);
    if(!ret)
    {
        printf("EVP_CIPHER_CTX_set_padding ERROR\n");
        return 0xffff;
    }

    EVP_DecryptUpdate(evp_ctx_dec, &plain[outl], &nBytesWritten, cipher_text, cipher_len);
    outl += nBytesWritten;

    EVP_DecryptFinal(evp_ctx_dec, &plain[outl], &nBytesWritten);
    outl += nBytesWritten;


    *plain_len = outl;

    return SUCCESS;
}

