/*******************
Author : Gunwoo Yun
Date : 22.11.09
Crypto : ARIA HMAC
*******************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "./inc/defines.h"
#include "./inc/hmacc.h"

EVP_CIPHER_CTX *evp_ctx_enc = NULL;
EVP_CIPHER_CTX *evp_ctx_dec = NULL;

//HMAC_CTX *hmac_ctx = NULL;

U1 cipher_type[12];

#if 0
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
#endif

U2 ARIA_Enc_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv)
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

int main(void)
{
	U2 ret = 0;
	U1 key_short[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	//U1 key_hmac[16] = {0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70};
	U1 key_hmac[16] = {"abcdefghijklmnop"};
	U1 iv[] = { 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 };

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

	
#if 1
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
