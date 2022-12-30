/*******************
Author : Gunwoo Yun
Date : 22.12.30
Crypto : ARIA HMAC-SHA256 SHA-256 GMAC RSA RSA_sign_verify ECDSA_sign_verify

*******************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
//#include <conio.h>
#include <curses.h>
#include <termios.h>
#include "./inc/defines.h"
#include "./inc/crypto_api.h"
#include "./inc/interface.h"
#include "./inc/example.h"
#include "./inc/system.h"

#define DEBUG_MODE

int main(int argc, char **argv)
{
	init_data();
	log_in();

	return 0;
}
