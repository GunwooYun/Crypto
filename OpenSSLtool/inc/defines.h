/**************
Author : Gunwoo Yun
Date : 22.11.25
**************/

#ifndef __DEFINES_H_
#define __DEFINES_H_

typedef unsigned char   U1;
typedef unsigned short  U2;
typedef unsigned int    U4;

#define SUCCESS 0x9000
#define IN
#define OUT

#define MODE_ECB 0x00
#define MODE_CBC 0x01
#define MODE_CTR 0x02
#define MODE_GCM 0x03

#define PADDING_BLOCK		0x01
#define NONE_PADDING_BLOCK	0x00

#define KEY_LEN_FILE_OFFSET 0x60 // 96
#define SYM_KEY_FILE_OFFSET 0x80 // 128

typedef enum
{
	ARIA = 1,
	HMAC_SHA256
}AlgType;


#endif
