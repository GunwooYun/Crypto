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
#include "./inc/crypto_api.h"

int main(void)
{
	U2 ret = 0;
	U1 key[16] = {"0123456789abcdef"};
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

	U1 msgDgst[3400] = {0x00, };
	U4 msgDgst_len = 0;
	U1 hmacData[30] = {"hello,world"};


	for(int i = 0; i < (U4)strlen(hmacData); i++)
		printf("%c",hmacData[i]);
	printf("\n");
	ret = Hmac(key, sizeof(key), hmacData, (U4)strlen(hmacData), msgDgst, &msgDgst_len);
	for(int i = 0; i < msgDgst_len; i++)
		printf("%x", msgDgst[i]);
	printf("\n");


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

	return 0;
}
