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

#define TEXT_LENGTH 64

int main(void)
{
	U2 ret = 0;
	U1 key[1024] = {0, };
	U1 iv[] = { 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 }; // 16bytes
	U1 aad[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };	// 16 Bytes

	U1 plain[TEXT_LENGTH] = {0x00, };
	U4 plain_len = 0;

	U1 cipher[TEXT_LENGTH + ARIA_BLOCK_SIZE] = {0x00, };
	U4 cipher_len = 0;

	U4 req_tag_len = 14;

	U1 tag[17] = {0x00, };
	U4 tag_len = 0;

	/* Plain Text get random value */
	ret = RAND_bytes(plain, TEXT_LENGTH);
	if(!ret)
    {
        printf("Random Plain Text Failed\n");
		return -1;
    }

	U1 msgDgst[3400] = {0x00, };
	U4 msgDgst_len = 0;
	U1 hmacData[30] = {"hello,world"};


	printf("******* SHA-256 TEST ************\n");
	DebugPrintArr(hmacData, (U4)strlen(hmacData));
	Sha256(hmacData, (U4)strlen(hmacData), msgDgst);
	DebugPrintArr(msgDgst, 32);

	printf("******* HMAC TEST ************\n");
	memset(msgDgst, 0, 3400);
	DebugPrintArr(hmacData, (U4)strlen(hmacData));
	ret = HmacSha256(key, sizeof(key), hmacData, (U4)strlen(hmacData), msgDgst, &msgDgst_len);
	DebugPrintArr(msgDgst, msgDgst_len);


	printf("******* Key ************\n");
	GenKey(128, key);
	DebugPrintArr(key, 128);

	printf("******* ARIA Encryption Start ************\n");
	printf("Plain Text\n");
	DebugPrintArr(plain, sizeof(plain));

	ret = EncryptARIA(key, PADDING_BLOCK, MODE_GCM, plain, sizeof(plain), cipher, &cipher_len, req_tag_len, tag, &tag_len, sizeof(iv), iv, sizeof(aad), aad);
	
	printf("Cipher Text / cipher len : %d\n", cipher_len);
	DebugPrintArr(cipher, cipher_len);

	printf("******* ARIA Decryption Start ************\n");

	memset(plain, 0, sizeof(plain)); // plain buffer init 0

	ret =  DecryptARIA(key, PADDING_BLOCK, MODE_GCM, cipher, cipher_len, plain, &plain_len, tag, tag_len, sizeof(iv), iv, sizeof(aad), aad);

	printf("Plain Text\n");
	DebugPrintArr(plain, plain_len);

	return 0;
}
