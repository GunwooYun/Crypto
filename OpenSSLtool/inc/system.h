/* System.h */
#ifndef __SYSTEM_H_
#define __SYSTEM_H_

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <termios.h>

#include "defines.h"
#include "crypto_api.h"

extern U1 systemKey[16];

extern U1 flag_need_init;
extern U1 flag_logged_in;
extern bool flag_system_verified;

enum log_in_step
{
    CHECK_ID = 0,
    CHECK_PW,
    CHECK_RE_PW,
};

extern char getKey(void);
extern U2 Hmac(IN U1 *key, IN U1 *msg, IN U4 msg_len, OUT U1 *md, OUT U4 *md_len);
extern int arrcmp(IN U1 *arr_a, IN U1 *arr_b, IN U4 len);
int verifyData(void);
void init_data(void);
void log_in(void);
int getStrLen(U1 *str, U4 strSize);

#endif
