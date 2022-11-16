/*******************
Author : Gunwoo Yun
Date : 22.11.16
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

int main(void)
{
	U2 ret = 0;
	U1 key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	U1 iv[] = { 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 }; // 16bytes
	U1 aad[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };	// 16 Bytes

	U1 plain[128] = {0x00, };
	U4 plain_len = 0;

	U1 cipher[128 + ARIA_BLOCK_SIZE] = {0x00, };
	U4 cipher_len = 0;

	U4 req_tag_len = 14;

	U1 tag[17] = {0x00, };
	U4 tag_len = 0;

	/* Plain Text get random value */
	ret = RAND_bytes(plain, 128);
	if(!ret)
    {
        printf("Random Plain Text Failed\n");
		return -1;
    }

	//U1 key_hmac[16] = {0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70};
	//U1 key_hmac[16] = {"abcdefghijklmnop"};

	//U1 msgDgst[3400] = {0x00, };
	//U4 msgDgst_len = 0;
	//U1 hmacData[30] = {"hello,world"};


	printf("******* Key ************\n");
	for(int i = 0; i < sizeof(key); i++)
		printf("%#x ", key[i]);
	printf("\n");

	printf("******* ARIA Encryption Start ************\n");
	printf("Plain Text\n");
	for(int i = 0; i < sizeof(plain); i++)
		printf("%#x ", plain[i]);
	printf("\n");

	ret = EncryptARIA(key, PADDING_BLOCK, MODE_GCM, plain, sizeof(plain), cipher, &cipher_len, req_tag_len, tag, &tag_len, sizeof(iv), iv, sizeof(aad), aad);
	if(cipher == NULL)
	{
		printf("cipher NULL\n");
		return 0xffff;
	}
	
	printf("cipher length : %d\n", cipher_len);

	printf("Cipher Text\n");
	for(int i = 0; i < cipher_len; i++)
		printf("%#x ", cipher[i]);
	printf("\n");

	printf("******* ARIA Decryption Start ************\n");

	memset(plain, 0, sizeof(plain)); // plain buffer init 0

	ret =  DecryptARIA(key, PADDING_BLOCK, MODE_GCM, cipher, cipher_len, plain, &plain_len, tag, tag_len, sizeof(iv), iv, sizeof(aad), aad);

	printf("Plain Text\n");
	for(int i = 0; i < plain_len; i++)
		printf("%#x ", plain[i]);
	printf("\n");

	//free(cipher);

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
