/*******************
Author : Gunwoo Yun
Date : 22.11.29
Crypto : ARIA HMAC-SHA256 SHA-256 GMAC RSA RSA_sign_verify ECDSA_sign_verify

*******************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "./inc/defines.h"
#include "./inc/crypto_api.h"
#include "./inc/interface.h"

U1 flag_need_init = 0;
U1 flag_logged_in = 0;
extern U1 KEK[32];

int arrcmp(IN U1 *arr_a, IN U1 *arr_b, IN U4 len)
{
	U1 *p_a = arr_a;
	U1 *p_b = arr_b;
	for(int i = 0; i < len; i++)
	{
		if(*(p_a++) != *(p_b++))
			return 1;
	}
	return 0;
}

void init_data()
{
	FILE *fp_data = NULL;
	U1 id_buf[32] = {0, };
	U1 pw_buf[32] = {0, };
	U1 re_pw_buf[32] = {0, };
	U1 salt[32] = {0, };
	U1 salted_pw[64] = {0, };
	U1 hashed_pw[32] = {0, };
	U4 writtenBytes = 0;


	fp_data = fopen("./.data", "rb");
	if(fp_data != NULL)
	{
		printf("Already Initialized\n");
		return;
	}

	printf("Initialize Data\n");
	printf("ID : ");
	gets(id_buf);
	while(1)
	{
	printf("PW : ");
	gets(pw_buf);
	printf("Re type PW : ");
	gets(re_pw_buf);

	if(!strcmp(pw_buf, re_pw_buf)) break;
	}

	/* Generate salt */
	GenCtrDRBG(sizeof(salt), salt);

	memcpy(salted_pw, salt, sizeof(salt) / 2);
	memcpy(salted_pw + (sizeof(salt) / 2), pw_buf, sizeof(pw_buf));
	memcpy(salted_pw + (sizeof(salt) / 2) + sizeof(pw_buf), salt + sizeof(salt) / 2, sizeof(salt) / 2);

	Sha256(salted_pw, sizeof(salted_pw), hashed_pw);


	fp_data = fopen("./.data", "wb");
	if(fp_data == NULL)
	{
		printf("file open failure\n");
		return;
	}
	writtenBytes = fwrite(id_buf, sizeof(U1) /* 1byte */, sizeof(id_buf), fp_data);
	assert(writtenBytes == 32);
	writtenBytes = fwrite(hashed_pw, sizeof(U1) /* 1byte */, sizeof(hashed_pw), fp_data);
	assert(writtenBytes == 32);
	writtenBytes = fwrite(salt, sizeof(U1) /* 1byte */, sizeof(salt), fp_data);
	assert(writtenBytes == 32);

	fclose(fp_data);

}

void log_in()
{
	U1 id[32] = {0, };
	U1 saved_hashed_pw[32] = {0, };
	U1 id_buf[32] = {0, };
	U1 pw_buf[32] = {0, };
	U1 salt[32] = {0, };
	U1 salted_pw[64] = {0, };
	U1 input_hashed_pw[32] = {0, };
	U4 readBytes = 0;

	FILE *fp_data = NULL;

	fp_data = fopen("./.data", "rb");
	if(fp_data == NULL)
	{
		init_data();
		return;
	}
	else
	{
		readBytes = fread(id, sizeof(U1), 32, fp_data); // fetch id
		assert(readBytes == 32);
		readBytes = fread(saved_hashed_pw, sizeof(U1), 32, fp_data); // fetch pw
		assert(readBytes == 32);
		readBytes = fread(salt, sizeof(U1), 32, fp_data); // fetch salt
		assert(readBytes == 32);


		printf("*** Log in ***\n");
		printf("ID : ");
		gets(id_buf);
		while(1)
		{
			printf("PW : ");
			gets(pw_buf);
			memset(salted_pw, 0, sizeof(salted_pw));
			memset(input_hashed_pw, 0, sizeof(input_hashed_pw));
			memcpy(salted_pw, salt, sizeof(salt) / 2);
			memcpy(salted_pw + (sizeof(salt) / 2), pw_buf, sizeof(pw_buf));
			memcpy(salted_pw + (sizeof(salt) / 2) + sizeof(pw_buf), salt + sizeof(salt) / 2, sizeof(salt) / 2);

			Sha256(salted_pw, sizeof(salted_pw), input_hashed_pw);

			if(!arrcmp(input_hashed_pw, saved_hashed_pw, 32))
			{
				break;
			}
			else
			{
				printf("password not correct!\n");
			}
		}

		/* Iterate hash 1000 times*/
		for(int i = 0; i < 1000; i++)
		{
			Sha256(input_hashed_pw, sizeof(input_hashed_pw), input_hashed_pw);
		}
		memset(KEK, 0, sizeof(KEK));
		Sha256(input_hashed_pw, sizeof(input_hashed_pw), KEK);

	}
	fclose(fp_data);
	printf("Log-in Success\n");
}


int main(int argc, char **argv)
{
	//flag_need_init = 0;
	//flag_logged_in = 0;

	//init_data();
	
	//log_in();

	//GenKeyAriaAes(0x00, 16);	
	//GenKeyAriaAes(0x01, 24);	
	//GenKeyAriaAes(0x02, 32);	

	//testAria();
	//testSha256();
	//testHmac();

	 testRSA_enc_dec();



	return 0;
}
