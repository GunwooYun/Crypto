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
	U1 hashed_id[32] = {0, };
	U1 pw_buf[32] = {0, };
	U1 re_pw_buf[32] = {0, };
	U1 salt[32] = {0, };
	const U1 salt_len = 32;
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
	printf("Create ID & Password\n");
	printf("ID (5 ~ 32byte) : ");
	fgets(id_buf, sizeof(id_buf), stdin);

	printf("PW : ");
	fgets(pw_buf, sizeof(pw_buf), stdin);

	while(1)
	{
	printf("Re type PW : ");
	fgets(re_pw_buf, sizeof(re_pw_buf), stdin);

	if(!strcmp(pw_buf, re_pw_buf)) break;
	}

	/* Generate salt (len : 32byte) */
	GenCtrDRBG(salt_len, salt);

	/* | salt (16byte) | password (32byte) | salt (16byte) | */
	memcpy(salted_pw, salt, sizeof(salt) / 2);
	memcpy(salted_pw + (sizeof(salt) / 2), pw_buf, sizeof(pw_buf));
	memcpy(salted_pw + (sizeof(salt) / 2) + sizeof(pw_buf), salt + sizeof(salt) / 2, sizeof(salt) / 2);

	/* Execute SHA-256 for ID */
	Sha256(id_buf, sizeof(id_buf), hashed_id);

	/* Execute SHA-256 for pw */
	Sha256(salted_pw, sizeof(salted_pw), hashed_pw);

	fp_data = fopen("./.data", "wb");
	if(fp_data == NULL)
	{
		printf("file open failure\n");
		return;
	}
	writtenBytes = fwrite(hashed_id, sizeof(U1) /* 1byte */, sizeof(hashed_id), fp_data);
	assert(writtenBytes == 32);
	writtenBytes = fwrite(hashed_pw, sizeof(U1) /* 1byte */, sizeof(hashed_pw), fp_data);
	assert(writtenBytes == 32);
	writtenBytes = fwrite(salt, sizeof(U1) /* 1byte */, sizeof(salt), fp_data);
	assert(writtenBytes == 32);

	fclose(fp_data);
}

void log_in()
{
	U1 saved_hashed_id[32] = {0, };
	U1 saved_hashed_pw[32] = {0, };
	U1 id_buf[32] = {0, };
	U1 pw_buf[32] = {0, };
	U1 input_hashed_id[32] = {0, };
	U1 input_hashed_pw[32] = {0, };
	U1 salt[32] = {0, };
	U1 salted_pw[64] = {0, };
	U4 readBytes = 0;

	FILE *fp_data = NULL;

	fp_data = fopen("./.data", "rb");
	if(fp_data == NULL)
	{
		init_data();
		return;
	}

	/* Fetch ID, PW, salt from data file */
	readBytes = fread(saved_hashed_id, sizeof(U1), 32, fp_data); // fetch id
	assert(readBytes == 32);
	readBytes = fread(saved_hashed_pw, sizeof(U1), 32, fp_data); // fetch pw
	assert(readBytes == 32);
	readBytes = fread(salt, sizeof(U1), 32, fp_data); // fetch salt
	assert(readBytes == 32);


	printf("*** Log in ***\n");
	while(1)
	{
		memset(id_buf, 0, sizeof(id_buf));
		printf("ID : ");
		fgets(id_buf, sizeof(id_buf), stdin);

		Sha256(id_buf, sizeof(id_buf), input_hashed_id);

		if(arrcmp(input_hashed_id, saved_hashed_id, 32))
		{
			continue;
		}

		printf("PW : ");
		fgets(pw_buf, sizeof(pw_buf), stdin);
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

	fclose(fp_data);
	printf("Log-in Success\n");
}


int main(int argc, char **argv)
{
	init_data();
	log_in();
	return 0;
}
