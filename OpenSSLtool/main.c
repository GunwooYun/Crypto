/*******************
Author : Gunwoo Yun
Date : 22.11.24
Crypto : ARIA HMAC-SHA256 SHA-256 GMAC RSA RSA_sign_verify ECDSA_sign_verify

*******************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "./inc/defines.h"
#include "./inc/crypto_api.h"

#define TEXT_LENGTH 64

U1 flag_need_init = 0;
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

void load_data()
{
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
}


int main(int argc, char **argv)
{
	U2 ret = 0;
	log_in();
	//log_in();
	//ret = GenKeyAriaAes(0x00, 0x10);
	//ret = GenkeyAriaAes(0x01, 32);
	//ret = GenKeyAriaAes(0x02, 24);
	//printf("ret2 : %d\n", ret);
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

	U1 msg[] = "Hello, world";
	U4 msg_len = sizeof(msg);;
	U1 ct[256 + 1] = {0, };
	U1 pt[4096] = {0, };

	U1 public_key[4096] = {0, };
	U1 private_key[4096] = {0, };

	U1 sign[32] = {0x00, };
	U4 sign_len = 0;

	U1 sign_R[32] = {0, };
	U1 sign_S[32] = {0, };

	EC_KEY *ec_key = NULL;
	ret = Gen_EC_key(NID_secp256k1, &ec_key);


	printf("******* ARIA Encryption Start ************\n");
	printf("Plain Text (lenth : %d)\n", sizeof(plain));
	DebugPrintArr(plain, sizeof(plain));

	ret = EncryptARIA(0x00, PADDING_BLOCK, MODE_ECB, plain, sizeof(plain), cipher, &cipher_len, req_tag_len, tag, &tag_len, sizeof(iv), iv, sizeof(aad), aad);
	
	printf("******* ARIA Decryption Start ************\n");
	memset(plain, 0, sizeof(plain)); // plain buffer init 0

	ret =  DecryptARIA(0x00, PADDING_BLOCK, MODE_ECB, cipher, cipher_len, plain, &plain_len, tag, tag_len, sizeof(iv), iv, sizeof(aad), aad);

	printf("Plain Text\n");
	DebugPrintArr(plain, plain_len);

#if 0
	printf("******* ECDSA Signification ************\n");
	ret = sign_ECDSA(ec_key, msg, msg_len, sign_R, sign_S);

	//DebugPrintArr(sign_R, 32);
	//DebugPrintArr(sign_S, 32);

	printf("******* ECDSA Verification ************\n");
	ret = verify_ECDSA(ec_key, msg, msg_len, sign_R, sign_S);


	RSA *rsa_key = NULL;
	ret = GenRsaKey(1024, &rsa_key, public_key, private_key);
	printf("******* RSA-PSS Signification ************\n");
	ret = sign_RSA_PSS(rsa_key, msg, msg_len, sign, &sign_len);
	ret = verify_RSA_PSS(rsa_key, msg, msg_len, sign, sign_len); 
	printf("******* RSA Encryption ************\n");
	ret = encrypt_RSAES_OAEP(rsa_key, msg, sizeof(msg), ct, &cipher_len);
	//ret = encrypt_RSAES_OAEP(rsa_key, msg, sizeof(msg), ct, &cipher_len);
	//printf("cipher length : %d\n", cipher_len);

	DebugPrintArr(ct, cipher_len);

	ret = decrypt_RSAES_OAEP(rsa_key, ct, cipher_len, pt, &msg_len);

	//ret = RSA_private_decrypt(cipher_len, ct, pt, rsa_key, RSA_PKCS1_OAEP_PADDING);

	printf("%s\n", pt);


	//printf("%s", private_key);
	//printf("%s", public_key);

	printf("******* DRBG TEST ************\n");
	ret = GenCtrDRBG(16, key);
	DebugPrintArr(key, 16);

	printf("******* GMAC TEST ************\n");
	ret = GmacGetTag(key, iv, sizeof(iv), aad, sizeof(aad), req_tag_len, tag, &tag_len); 
	DebugPrintArr(tag, req_tag_len);

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
#endif

	return 0;
}
