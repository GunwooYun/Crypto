#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "../inc/hmacc.h"
#include "../inc/defines.h"

HMAC_CTX *hmac_ctx;
U2 HMAC_init(IN U1 *key, IN U4 key_len)
{
    int ret = 0;

    hmac_ctx = HMAC_CTX_new();
    if(hmac_ctx == NULL){
        printf("HMAC_CTX_new() is NULL\n");
        return 1;
    }

    ret = HMAC_Init_ex(hmac_ctx, key, (int)key_len, EVP_sha256(), NULL);
    if(!ret){
        printf("HMAC_Init_ex failed\n");
        return 1;
    }
    return 0x9000;
}

U2 HMAC_update(IN U1 *data, IN U4 data_len)
{
    int ret = 0;

    ret = HMAC_Update(hmac_ctx, data, (size_t)data_len);
    printf("update ret : %d\n", ret);

    return 0x9000;
}

U2 HMAC_final(OUT U1 *md, OUT U4 *md_len)
{
    int ret = 0;
    ret = HMAC_Final(hmac_ctx, md, md_len);
    printf("final ret : %d\n", ret);

    return 0x9000;
}
