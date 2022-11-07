/**************
Author : Gunwoo Yun
Date : 22.11.07
Crypto : ARIA
**************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
//#include "aria.h"

typedef unsigned char	U1;
typedef unsigned short	U2;
typedef unsigned int	U4;

#define SUCCESS 0x9000
#define IN
#define OUT

#if 0
U2 EncryptARIAinit(const EVP_CIPHER *ec, EVP_CIPHER_CTX)
{
}
#endif

U2 EncryptARIA(IN U1 *plain_text, OUT U1 *encrypted_text)
{
	U2 ret = 0x0000;
	U1 *cipher_buf = NULL;
	U4 outl = 0;
	U4 nBytesWritten = 0;
	U1 enc_buf[100] = {0x00, };
	U1 key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	U4 nRepeatUpdate = 0;
	U1 decrypted_buf[100] = {0x00, };

	const EVP_CIPHER *evp_cipher = EVP_aria_128_ecb();
	EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();

	if(ctx_enc == NULL)
	{
		printf("ctx_enc is NULL\n");
		ret = 0x0f10;
		return ret;
	}

	/*
	ret = EVP_EncryptInit_ex(ctx_enc, evp_cipher, NULL, NULL, NULL);

	if(!ret)
	{
		printf("EVP_EncryptInit_ex ERROR\n");
		ret = 0x0f11;
		return ret;
	}
	*/

	ret = EVP_CIPHER_CTX_set_padding(ctx_enc, 0);
	if(!ret)
	{
		printf("EVP_CIPHER_CTX_set_padding ERROR\n");
		ret = 0x0f12;
		return ret;
	}
	/*
	printf("Generate key -->\t");

	U1 *key = (U1 *)malloc(EVP_CIPHER_CTX_key_length(ctx_enc));
	if(key == NULL)
	{
		printf("malloc for key failed \n");
		ret = 0x0fa0;
		return ret;
	}
	ret = RAND_bytes(key,EVP_CIPHER_CTX_key_length(ctx_enc)); 
	if(!ret)
	{
		printf("RAND_bytes ERROR\n");
		ret = 0x0fc1;
		return ret;
	}
	printf("okay\n");
	*/

	ret = EVP_EncryptInit_ex(ctx_enc, evp_cipher, NULL, key, NULL);

	if(!ret)
	{
		printf("EVP_EncryptInit_ex ERROR\n");
		ret = 0x0f11;
		return ret;
	}

	cipher_buf = (U1 *)malloc(strlen((const char*)plain_text) + EVP_CIPHER_CTX_block_size(ctx_enc));
	if(cipher_buf == NULL)
	{
		printf("cipher buf malloc failed\n");
		ret = 0x0f33;
		return ret;
	}
	//printf("block size : %d\n", EVP_CIPHER_CTX_block_size(ctx_enc));

	nRepeatUpdate = (int)strlen((char *)plain_text) / 16;

	for(int i = 0; i < nRepeatUpdate; i++)
	{
		EVP_EncryptUpdate(ctx_enc, &cipher_buf[nBytesWritten], &nBytesWritten, &plain_text[nBytesWritten], (int)strlen((char *)plain_text));
	}

	EVP_EncryptFinal_ex(ctx_enc, &cipher_buf[nBytesWritten], &nBytesWritten);

	//EVP_CIPHER_CTX_free(ctx_enc);

	printf("cipher text is\n");

	for(int i= 0; i < strlen((const char*)cipher_buf); i++)
		printf("%#x ", cipher_buf[i]);

	//printf("written bytes : %d\n", nBytesWritten);
	//outl += nBytesWritten;
	//printf("outl : %d\n", outl);

	/*
	for(int i= 0; i < strlen((const char*)enc_buf); i++)
		printf("%#x ", enc_buf[i]);
		*/
	/*
	EVP_EncryptUpdate(ctx_enc, &enc_buf[outl], &nBytesWritten, &plain_text[outl], (int)strlen((char *)plain_text));

	printf("written bytes : %d\n", nBytesWritten);
	outl += nBytesWritten;
	printf("outl : %d\n", outl);
	*/

	/*
	printf("key size : %d\n", (int)strlen(key));

	for(int i= 0; i < strlen((const char*)key); i++)
		printf("%#x ", key[i]);
		*/

	/*
	for(int i= 0; i < strlen((const char*)enc_buf); i++)
		printf("%#x ", enc_buf[i]);
		*/
	nBytesWritten = 0;

	ret = EVP_DecryptInit_ex(ctx_enc, evp_cipher, NULL, key, NULL);

	if(!ret)
	{
		printf("EVP_DecryptInit_ex ERROR\n");
		ret = 0x0f11;
		return ret;
	}
	for(int i = 0; i < nRepeatUpdate; i++)
	{
		EVP_DecryptUpdate(ctx_enc, &decrypted_buf[nBytesWritten], &nBytesWritten, &plain_text[nBytesWritten], (int)strlen((char *)plain_text));
	}

	EVP_EncryptFinal_ex(ctx_enc, &cipher_buf[nBytesWritten], &nBytesWritten);

	

	return SUCCESS;
}

int main(void)
{
	U2 ret = 0;

	char plain_text[100] = {"hello, world, abcdefghijklmnop"};
	U1 encrypted_text[16] = {0x00, };

	//printf("%s\n", plain_text);

	ret = EncryptARIA((U1 *)plain_text, encrypted_text);

	//printf("ret : %#x\n", ret);





#if 0 // ARIA
	int ret = 0;
	ARIA_KEY encKey, decKey;
	U1 user_key[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	int user_key_len = sizeof(user_key);

	U1 plain_text[] = {0x11, 0x11,0x11,0x11, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb};
	int plain_text_len = sizeof(plain_text);

	U1 encrypted_text[100] = {0x00, };
	U1 decrypted_text[100] = {0x00, };

	//U1 enc_key[16] = {0x00, };
	printf("user key length : %d\n", user_key_len);
	printf("plain text length : %d\n", plain_text_len);

	ret = aria_set_encrypt_key(user_key, 128, &encKey);
	if(ret < 0)
		printf("[CODE : %d] aria_set_encrypt_key ERROR\n", ret);

	ret = aria_set_decrypt_key(user_key, 128, &decKey);
	if(ret < 0)
		printf("[CODE : %d] aria_set_decrypt_key ERROR\n", ret);

	for(int i = 0; i < strlen(plain_text); i++)
		printf("%#x ", plain_text[i]);
	printf("\n");

	aria_encrypt(plain_text, encrypted_text, &encKey);

	for(int i = 0; i < strlen(encrypted_text); i++)
		printf("%#x ", encrypted_text[i]);
	printf("\n");

	aria_encrypt(encrypted_text, decrypted_text, &decKey);

	for(int i = 0; i < strlen(decrypted_text); i++)
		printf("%#x ", decrypted_text[i]);
	printf("\n");
#endif

	return 0;
}
