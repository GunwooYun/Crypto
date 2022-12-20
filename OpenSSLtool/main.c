/*******************
Author : Gunwoo Yun
Date : 22.12.17
Crypto : ARIA HMAC-SHA256 SHA-256 GMAC RSA RSA_sign_verify ECDSA_sign_verify

*******************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "./inc/defines.h"
#include "./inc/crypto_api.h"
#include "./inc/interface.h"
#include "./inc/example.h"

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

int getStrLen(U1 *str, U4 strSize)
{
	U1 *pStr = str;
	int cnt = 0;
	while(cnt < strSize)
	{
		if(*pStr == '\n')
		{
			*pStr = 0;
			break;
		}
		cnt++;
		pStr++;
		if(cnt >= strSize)
		{
			while(getchar() != '\n');
			break;
		}
	}
	/*
	while((*(pStr++) != '\n'))
	{
		if(cnt >= (strSize-1))
		{
			while(getchar() != '\n');
			break;
		}
		cnt++;
	}
	*/
	return cnt;
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

	U4 id_buf_len = 0;
	U4 pw_buf_len = 0;
	char ch;
	int ch_idx = 0;


	fp_data = fopen("./.data", "rb");
	if(fp_data != NULL)
	{
		printf("Already Initialized\n");
		return;
	}

	printf("Initialize Data\n");
	printf("Create ID & Password\n");
	do{
		printf("ID (len : 5 ~ 20) : ");
		fgets(id_buf, sizeof(id_buf), stdin);
		//printf("id length : %d\n", chkStrLen(id_buf, 32));

		/* fflush buffer of stdin*/
		/*
		if(strlen(id_buf) >= 31 && id_buf[30] != '\n')
		{
			while(getchar() != '\n');
		}
		*/
		//id_buf_len = strlen(id_buf) - 1; // strlen read '\n'
		id_buf_len = getStrLen(id_buf, 32);
		//printf("id_buf_len : %d\n", id_buf_len);
		if(id_buf_len >= 5 && id_buf_len <= 20) break; // 5 <= length of ID <= 20
		printf("id length incorrect\n");
	}while(1);

	do{
		printf("PW (len : 5 ~ 30) : ");
		fgets(pw_buf, sizeof(pw_buf), stdin);
		/* fflush buffer of stdin*/
			/*
		if(strlen(pw_buf) >= 31 && pw_buf[30] != '\n')
		{
			while(getchar() != '\n');
		}
		*/
		//pw_buf_len = strlen(pw_buf) - 1; // pw_buf + '\n'
		pw_buf_len = getStrLen(pw_buf, 32);
		//printf("pw_buf_len : %d\n", pw_buf_len);
		if(pw_buf_len >= 5 && pw_buf_len <= 30) break; // 5 <= length of PW <= 30
		printf("password length incorrect\n");

	}while(1);
	printf("pw buf : ");
	for(int i = 0; i < 32; i++)
	{
		printf("%x ", pw_buf[i]);
	}
	printf("\n");

	do{
		memset(re_pw_buf, 0, 32);
		printf("Re type PW  (len : 5 ~ 30) : ");
		fgets(re_pw_buf, sizeof(re_pw_buf), stdin);
		/* fflush buffer of stdin*/
			/*
		if(strlen(pw_buf) >= 31 && pw_buf[30] != '\n')
		{
			while(getchar() != '\n');
		}
		*/
		//pw_buf_len = strlen(pw_buf) - 1; // pw_buf + '\n'
		pw_buf_len = getStrLen(re_pw_buf, 32);
		printf("re pw_buf_len : %d\n", pw_buf_len);
		if(pw_buf_len >= 5 && pw_buf_len <= 30)
		{
			if(!strcmp(pw_buf, re_pw_buf))
			{
				break;
			}
			else
			{
				printf("re password not same\n");
			}
		}
		else
		{
			printf("password length incorrect\n");
		}
	}while(1);

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
	/* Write hashed id 32bytes */
	writtenBytes = fwrite(hashed_id, sizeof(U1) /* 1byte */, sizeof(hashed_id), fp_data);
	assert(writtenBytes == 32);

	/* Write hashed pw 32bytes */
	writtenBytes = fwrite(hashed_pw, sizeof(U1) /* 1byte */, sizeof(hashed_pw), fp_data);
	assert(writtenBytes == 32);


	/* Write salt 32bytes */
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

	U4 bufLen = 0;

	bool loginLoop = true;
	U1 flag_id_passed = 0;

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
	printf("saved hashed password : ");
	for(int i = 0; i < 32; i++)
	{
		printf("%x ", saved_hashed_pw[i]);
	}
	printf("\n");
	readBytes = fread(salt, sizeof(U1), 32, fp_data); // fetch salt
	assert(readBytes == 32);


	printf("*** Log in ***\n");
	while(loginLoop)
	{
		switch(flag_id_passed)
		{
			case 0 :
				memset(id_buf, 0, sizeof(id_buf));
				printf("ID (len : 5 ~ 20) : ");
				fgets(id_buf, sizeof(id_buf), stdin);

				bufLen = getStrLen(id_buf, 32);
				if(bufLen < 5 || bufLen > 20)
				{
					printf("id length incorrect\n");
					break;
				}

				/* Get hashed input ID */
				Sha256(id_buf, sizeof(id_buf), input_hashed_id);

				if(!arrcmp(input_hashed_id, saved_hashed_id, 32))
				{
					flag_id_passed = 1;
				}
				break;

			case 1 :
				memset(pw_buf, 0, sizeof(pw_buf));
				printf("PW (len : 5 ~ 30) : ");
				fgets(pw_buf, sizeof(pw_buf), stdin);

				bufLen = getStrLen(pw_buf, 32);
				if(bufLen < 5 || bufLen > 20)
				{
					printf("pw length incorrect\n");
					break;
				}
				printf("login pw buf : ");
				for(int i = 0; i < 32; i++)
				{
					printf("%x ", pw_buf[i]);
				}
				printf("\n");
				memset(salted_pw, 0, sizeof(salted_pw));
				memset(input_hashed_pw, 0, sizeof(input_hashed_pw));

				/* | salt (16byte) | password (32byte) | salt (16byte) | */
				memcpy(salted_pw, salt, sizeof(salt) / 2);
				memcpy(salted_pw + (sizeof(salt) / 2), pw_buf, sizeof(pw_buf));
				memcpy(salted_pw + (sizeof(salt) / 2) + sizeof(pw_buf), salt + sizeof(salt) / 2, sizeof(salt) / 2);

				/* Get hashed input password */
				Sha256(salted_pw, sizeof(salted_pw), input_hashed_pw);

				printf("input hashed password : ");
				for(int i = 0; i < 32; i++)
				{
					printf("%x ", input_hashed_pw[i]);
				}
				printf("\n");

				if(!arrcmp(input_hashed_pw, saved_hashed_pw, 32))
				{
					loginLoop = false;
				}
				else
				{
					printf("password not correct!\n");
				}
				break;
		}
	}

	/* Iterate hash 1000 times*/
	for(int i = 0; i < 1000; i++)
	{
		Sha256(input_hashed_pw, sizeof(input_hashed_pw), input_hashed_pw);
	}

	/* Generate KEK using SHA-256 */
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
