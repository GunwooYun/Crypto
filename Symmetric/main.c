/***********************************
 *  DES : Data Encryption Standard
 *  Author : GunwooYun
 **********************************/

#include <stdio.h>
#include <string.h>

typedef double uint64_t;
typedef unsigned char uint8_t;


uint8_t ip_table[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7

};

void InitPermutation(char* plain_text)
{
    
}

int main(int argv, char** argc)
{
    uint8_t raw_text[100]; // Input string
    uint8_t plain_text[8] = {0,}; // plain text for 64bit
    uint64_t tmp_text = 0;
    char ch;
    //uint64_t * ptr_text = NULL;
    printf("64bit(8 bytes) string : ");
    gets(raw_text);
    printf("%d\n", strlen(raw_text));

    /* Check string <= 64bit */
    if(strlen(raw_text) > 8)
    {
        printf("string excced 64 bit");
        return 0;
    }

    memcpy(plain_text, raw_text, 8);
    memcpy(&tmp_text, raw_text, 8);
    for(int i = 0; i < 7; i++)
    {
        printf("%c ",plain_text[i]);
    }


    return 0;
}