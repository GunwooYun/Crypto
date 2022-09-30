/***********************************
 *  DES : Data Encryption Standard
 *  Author : GunwooYun
 **********************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>

//typedef double uint64_t;
//typedef unsigned char uint8_t;


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

uint8_t pc_1_table[] = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
};

uint8_t replace_table[48] = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32 };

void InitPermutation(char* plain_text)
{
    
}

int main(int argv, char** argc)
{
    uint8_t raw_text[100]; // Input string
    uint8_t plain_text[8] = {0,}; // plain text for 64bit
    uint8_t bit_one = 0;
    uint64_t tmp_text = 0;
    uint64_t permutated_text = 0;
    uint32_t a;

    puts("text : ");
    gets(raw_text);

    //printf("string length : %d\n", strlen(raw_text));

    if(strlen(raw_text) > 8)
    {
        printf("excced 64bit\n");
        return 1;
    }
    else
    {
        memcpy(&tmp_text, raw_text, 8);
    }

    //bit_one |= bit_one << 1;
    printf("index num : ");
    for(int i = 0; i < 64; i++)
    {
        printf("%d ", i+1);
    }
    
    printf("\nplain txt : ");
    for(int i = 0; i < 64; i++)
    {
        bit_one = (tmp_text >> i) & 0x01;
        printf("%d ", bit_one);
        //if((i % 8) == 7 && i != 0) printf("\n");
    }
    printf("\n");

    printf("shift txt : ");
    for(int i = 0; i < 64; i++)
    {
        bit_one = (tmp_text >> (ip_table[i]-1)) & 0x01;
        printf("%d ", bit_one);
      permutated_text |= (bit_one << i);
    }
    
    //printf("%#x\n", tmp_text);
    //printf("%d\n", sizeof(plain_text));
    return 0;
}