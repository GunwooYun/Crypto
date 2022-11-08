/**************
Author : Gunwoo Yun
Date : 22.11.08
Crypto : ARIA
**************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "./inc/defines.h"

EVP_CIPHER_CTX *evp_ctx_enc = NULL;
EVP_CIPHER_CTX *evp_ctx_dec = NULL;

U1 cipher_type[12];

#if 1 
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
#endif


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

#if 0
U2 ARIA_Dec_Update(IN U1 padding_flag, IN U1 *plain_text, IN U4 plain_len,  OUT U1 *cipher, OUT U4 *cipher_len)

U2 EncryptARIA(IN U1 padding_flag, IN U1 *plain_text, IN U4 plain_len,  OUT U1 *cipher, OUT U4 cipher_len)
{
	U2 ret = 0x0000;
	U4 outl = 0;
	U4 outdl = 0;
	U4 nBytesWritten = 0;
	U1 enc_buf[100] = {0x00, };
	U1 key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	U1 decrypted_buf[100] = {0x00, };



	const EVP_CIPHER *evp_cipher_enc = EVP_get_cipherbyname(cipher_type);
	evp_ctx_enc = EVP_CIPHER_CTX_new();




	printf("outl : %d\n", outl);

	printf("cipher text\n");

	for(int i= 0; i < outl; i++)
		printf("%#x ", cipher_buf[i]);
	printf("\n");

	EVP_CIPHER_CTX_free(evp_ctx_enc);

	ret = EVP_DecryptInit_ex(evp_ctx_dec, evp_cipher_dec, NULL, key, NULL);

	if(!ret)
	{
		printf("EVP_DecryptInit_ex ERROR\n");
		return 0xffff;
	}

	EVP_DecryptUpdate(evp_ctx_dec, &decrypted_buf[outdl], &nBytesWritten, cipher_buf, outl);
	outdl += nBytesWritten;

	EVP_DecryptFinal_ex(evp_ctx_dec, &decrypted_buf[outdl], &nBytesWritten);
	outdl += nBytesWritten;

	printf("outdl : %d\n", outdl);

	
	for(int i= 0; i < outdl; i++)
		printf("%c ", (char)decrypted_buf[i]);

	return SUCCESS;
}

#endif

int main(void)
{
	U2 ret = 0;
	U1 key_short[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	U1 iv[] = { 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 };

	U1 plain_text_short[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
							 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 };

	U1 cipher_text[100] = {0x00, };
	U4 cipher_len = 0;

	ret = ARIA_Enc_Init(key_short, MODE_ECB, sizeof(iv), iv);
	if(ret == SUCCESS)
		printf("init success\n");

	ret = ARIA_Enc_Update(PADDING_BLOCK, plain_text_short, sizeof(plain_text_short),  cipher_text, &cipher_len);
	if(ret == SUCCESS)
		printf("init success\n");
	return 0;
}
