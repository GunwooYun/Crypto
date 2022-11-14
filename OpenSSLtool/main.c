/*******************
Author : Gunwoo Yun
Date : 22.11.14
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

EVP_CIPHER_CTX *evp_ctx_enc_gcm = NULL;
EVP_CIPHER_CTX *evp_ctx_dec_gcm = NULL;
U1 cipher_type_gcm[12];

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

	U4 req_tag_len = 14;

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

	printf("******* ARIA Encryption Start ************\n");
	printf("Plain Text\n");
	for(int i = 0; i < sizeof(plain_text_short); i++)
		printf("%#x ", plain_text_short[i]);
	printf("\n");
	ret = ARIA_Enc_Init(key_short, MODE_GCM, sizeof(iv), iv, sizeof(aad), aad);
	if(ret != SUCCESS)
	{
		printf("aria gcm enc init failed\n");
		return 1;
	}

	ret = ARIA_Enc_Update(PADDING_BLOCK, MODE_GCM, plain_text_short, sizeof(plain_text_short), cipher_text, &cipher_len, req_tag_len, tag, &tag_len);
	if(ret != SUCCESS)
	{
		printf("aria gcm enc update failed\n");
		return 1;
	}
	printf("Cipher Text\n");
	for(int i = 0; i < cipher_len; i++)
		printf("%#x ", cipher_text[i]);
	printf("\n");

	//cipher_text[0] = 0xff;

	printf("******* ARIA GCM Decryption Start ************\n");
	printf("Cipher Text\n");
	for(int i = 0; i < cipher_len; i++)
		printf("%#x ", cipher_text[i]);
	printf("\n");

	ret = ARIA_Dec_Init(key_short, MODE_GCM, sizeof(iv), iv, sizeof(aad), aad);
	if(ret != SUCCESS)
	{
		printf("aria gcm dec init failed\n");
		return 1;
	}

	ret = ARIA_Dec_Update(PADDING_BLOCK, cipher_text, cipher_len, plain_text, &plain_len, tag, tag_len);
	if(ret != SUCCESS)
	{
		printf("aria gcm dec update failed\n");
		return 1;
	}
	printf("Plain Text\n");
	for(int i = 0; i < plain_len; i++)
		printf("%#x ", plain_text[i]);
	printf("\n");

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
