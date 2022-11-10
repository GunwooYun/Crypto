/*******************
Author : Gunwoo Yun
Date : 22.11.10
Crypto : ARIA HMAC
*******************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "./inc/defines.h"
#include "./inc/hmacc.h"
#include "./inc/aria.h"

EVP_CIPHER_CTX *evp_ctx_enc = NULL;
EVP_CIPHER_CTX *evp_ctx_dec = NULL;
//U4 outl = 0;
U1 cipher_type[12];

void GenMasterKey(void)
{
}
U2 GenSymKey(IN U1 symKeyIndex, IN U1 algType, IN U1 blockMode, IN U1 keyLen)
{
}

U2 ARIA_Gcm_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv, IN U2 add_len, IN U1 *aad)
{
    U4 key_len = 16;
    //U1 cipher_type[12] = {0x00, };
    U2 ret = 0x0000;
	U4 outl = 0;

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

	if(block_mode == MODE_GCM)
	{
		ret = EVP_EncryptUpdate(evp_ctx_enc, NULL, (int *)&outl, (const unsigned char*)aad, sizeof(aad));
		if(!ret)
		{
			printf("EVP_EncryptUpdate aad ERROR\n");
			return 0xffff;
		}
	}

    return 0x9000;
}

U2 ARIA_Gcm_Update(IN U1 padding_flag, IN U1 *plain_text, IN U4 plain_len, OUT U1 *cipher, OUT U4 *cipher_len)
{
	U2 ret = 0x0000;
    U1 *cipher_buf = NULL;
    U4 cipher_buf_len = 0;
    int nBytesWritten = 0;
	U4 require_tag_len = 14;

	U4 outl = 0;

    ret = EVP_CIPHER_CTX_set_padding(evp_ctx_enc, padding_flag);
    if(!ret)
    {
        printf("EVP_CIPHER_CTX_set_padding ERROR\n");
        return 0xffff;
    }

	ret = EVP_EncryptUpdate (evp_ctx_enc, (unsigned char *)&cipher_buf[outl], (int *)&nBytesWritten, (const unsigned char *)plain_text, (int)plain_len);
    if(!ret)
    {
        printf("EVP_EncryptUpdate ERROR\n");
        return 0xffff;
    }
	outl += nBytesWritten;

	ret = EVP_EncryptFinal (evp_ctx_enc, (unsigned char *)&cipher_buf[outl], (int *)&nBytesWritten);
    if(!ret)
    {
        printf("EVP_EncryptFinal ERROR\n");
        return 0xffff;
    }
	outl += nBytesWritten;


	memcpy(cipher, cipher_buf, nBytesWritten);

}

U2 ARIA_Gcm_Final(IN U1 require_tag_len, OUT U1 *tag, OUT U4 *tag_len)
{
	U4 tag_buf_len = 0;
	U1 tag_buf[17] = {0x00, };
	U4 ret = 0;

	if(require_tag_len > 16 || require_tag_len < 12){
		printf("required tag length wrong\n");
		return 0xffff;
	}

	ret = EVP_CIPHER_CTX_ctrl (evp_ctx_enc, EVP_CTRL_GCM_GET_TAG, (int)require_tag_len, (unsigned char *)tag_buf);

	tag_buf_len = strlen(tag_buf);
	memcpy(tag, tag_buf, tag_buf_len);
	*tag_len = tag_buf_len;
}

int main(void)
{
	U2 ret = 0;
	U1 key_short[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	//U1 key_hmac[16] = {0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70};
	U1 key_hmac[16] = {"abcdefghijklmnop"};
	U1 iv[] = { 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 }; // 16bytes
	U1 AAD[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };	// 16 Bytes

	U1 plain_text_short[128] = {0x00, };
	U1 plain_text_long[512] = {0x00, };
	U1 plain_text_longlong[1024] = {0x00, };

	U1 cipher_text[3400] = {0x00, };
	U4 cipher_len = 0;

	U1 plain_text[3400] = {0x00, };
	U4 plain_len = 0;

	U1 msgDgst[3400] = {0x00, };
	U4 msgDgst_len = 0;
	U1 hmacData[30] = {"hello,world"};

	U1 *pSelectedText = NULL;

	U4 nReqTagLen = 14;

	U1 tag[17] = {0x00, };
	U4 tag_len = 0;

	U1 aad[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };	// 16 Bytes

	ret = RAND_bytes(plain_text_short, 128);
	if(!ret)
    {
        printf("RAND_bytes ERROR\n");
		return 1;
    }
	ret = RAND_bytes(plain_text_long, 512);
	if(!ret)
    {
        printf("RAND_bytes ERROR\n");
		return -1;
    }
	ret = RAND_bytes(plain_text_longlong, 1024);
	if(!ret)
    {
        printf("RAND_bytes ERROR\n");
		return -1;
    }

	pSelectedText = plain_text_short; // Select short text


	ret = ARIA_Gcm_Init(key_short, MODE_GCM, sizeof(iv), iv, sizeof(aad), aad);
	if(ret != SUCCESS)
	{
		printf("aria gcm init failed\n");
		return 1;
	}

	ret = ARIA_Gcm_Update(PADDING_BLOCK, pSelectedText, sizeof(pSelectedText), cipher_text, &cipher_len)
	if(ret != SUCCESS)
	{
		printf("aria gcm update failed\n");
		return 1;
	}

	ret = ARIA_Gcm_Final(nReqTagLen, tag, &tag_len)
	if(ret != SUCCESS)
	{
		printf("aria gcm final failed\n");
		return 1;
	}
	
#if 0
	ret = HMAC_init(key_hmac, sizeof(key_hmac));
	if(ret != SUCCESS)
	{
		printf("hmac init failed\n");
		return 1;
	}
	printf("hmacData : %d\n", (int)strlen(hmacData));

	ret = HMAC_update(hmacData, strlen(hmacData));
	if(ret != SUCCESS)
	{
		printf("hmac init failed\n");
		return 1;
	}

	ret = HMAC_final(msgDgst, &msgDgst_len);
	if(ret != SUCCESS)
	{
		printf("hmac init failed\n");
		return 1;
	}


	printf("********* Message Digest ************\n");
	for(int i= 0; i < msgDgst_len; i++)
		printf("%#x ", msgDgst[i]);
	printf("\n");

	printf("********* Plain Text ************\n");
	for(int i= 0; i < sizeof(plain_text_short); i++)
		printf("%#x ", plain_text_short[i]);
	printf("\n");
	ret = ARIA_Enc_Init(key_short, MODE_ECB, sizeof(iv), iv);

	ret = ARIA_Enc_Update(NONE_PADDING_BLOCK, plain_text_short, sizeof(plain_text_short),  cipher_text, &cipher_len);
	printf("********* Cipher Text ************\n");
	for(int i= 0; i < cipher_len; i++)
		printf("%#x ", cipher_text[i]);
	printf("\n");

	ret = ARIA_Dec_Init(key_short, MODE_ECB, sizeof(iv), iv);

	ret = ARIA_Dec_Update(NONE_PADDING_BLOCK, cipher_text, cipher_len,  plain_text, &plain_len);

	printf("********* Encrypted Text ************\n");
	for(int i= 0; i < plain_len; i++)
		printf("%#x ", plain_text[i]);
	printf("\n");

#endif

	return 0;
}
