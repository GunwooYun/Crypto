/**************
Author : Gunwoo Yun
Date : 22.11.07
Crypto : ARIA
**************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <openssl/evp.h>
//#include <openssl/aria.h>
#include "aria.h"

typedef unsigned char	U1;
typedef unsigned short	U2;
typedef unsigned int	U4;

int main(void)
{
	int ret = 0;
	ARIA_KEY ariaKey;
	U1 user_key[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	int user_key_len = sizeof(user_key);

	U1 plain_text[] = {0x11, 0x11,0x11,0x11, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb};
	int plain_text_len = sizeof(plain_text);

	U1 enc_key[16] = {0x00, };
	printf("user key length : %d\n", user_key_len);
	printf("plain text length : %d\n", plain_text_len);

	ret = aria_set_encrypt_key(user_key, 128, &ariaKey);
	if(ret < 0)
		printf("[CODE : %d] aria_set_encrypt_key ERROR\n", ret);

	


	return 0;
}
