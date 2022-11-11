/***********************************
 *  DES : Data Encryption Standard
 *  Author : GunwooYun
 **********************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "defines.h"

/* Initial Permutation Table */
U1 init_perm[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7

};

/* Final Permutation Table */
U1 final_perm[] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47,
    15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22,
    62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36,
    4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11,
    51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58,
    26, 33, 1, 41, 9, 49, 17, 57, 25
    };

U1 pc_1_table[] = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
};

U1 replace_table[48] = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32 };

/* Key source is rotated to left shift on each round */
U1 key_rotation[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1 };

/* Execute Permutation */
U1* ExecPermutation(char* pTxt, U1* ip_tbl)
{
    U1 idx = 0;
    U1 pos = 0; 
    U1 bin = 0x00;

    U1* permed_data = (U1 *)malloc(8 * sizeof(U1));
    if(permed_data == NULL){
        printf("malloc failed for permed_data\n");
        return NULL;   
    }

    for(int i = 0; i < 64; i++){
        idx = (ip_tbl[i] - 1) / 8;
        pos = (ip_tbl[i] - 1) % 8;

        bin = (pTxt[i] >> (7 - pos)) & 0x01;

        idx = i / 8;
        pos = i % 8;

        permed_data[idx] |= (bin << (7 - pos));
    }
    return permed_data;
}

void RoundFunc()
{
    /* Round Function repeat 16 times */

}

void PrintBinary(char* txt)
{
    /* txt length should be 64bit */
    int cnt = 0;
    for(int i = 0; i < 8; i++)
    {
        for(int j = 7; j >= 0; j--)
        {
            printf("%d", (txt[i] >> j) & 0x01);
            if(cnt == 3)
            {
                printf(" ");
                cnt = 0;
            }
            else
                cnt++;
        }
    }
    
}

int main(int argv, char** argc)
{
    U1 plain_text[8] = "abcdefgh";
    U1 perm_text[8] = {0x00, };
    U1* permed_text = NULL;
   // U1* plained_text = NULL;

    printf("plain text : ");
    PrintBinary(plain_text);
    printf("\n");

    permed_text = ExecPermutation(plain_text, init_perm);
    if(permed_text == NULL){
        printf("error");
        return 1;
    }

    printf("permed text : ");
    PrintBinary(permed_text);

/*
    plained_text = ExecPermutation(permed_text, final_perm);
    if(plained_text == NULL){
        printf("error");
        return 1;
    }

    printf("plain text : ");
    PrintBinary(plained_text);
*/

    free(permed_text);
  //  free(plained_text);


    #ifdef SKIP
    U1 input_text[100]; // Input string
    U1 plain_text[8] = {0,}; // plain text for 64bit
    U1 bit_one = 0;
    uint64_t tmp_text = 0;
    uint64_t permutated_text = 0;
    uint32_t a;

    U1 str[100] = "abcdefgh";
    printf("%s\n", str);

    for(int i = 0; i < strlen(str); i++)
        printf("%#x ", str[i]);
    printf("\n");

    int cnt = 0;
    for(int i = 0; i < strlen(str); i++)
    {
        for(int j = 7; j >= 0; j--)
        {
            printf("%d", (str[i] >> j) & 0x01);
            if(cnt == 4)
            {
                printf(" ");
                cnt = 0;
            }
            cnt++;
        }
    }
    #endif

    #ifdef SKIP
    puts("text : ");
    gets(input_text);

    //printf("string length : %d\n", strlen(raw_text));

    if(strlen(input_text) > 8)
    {
        printf("excced 64bit\n");
        return 1;
    }
    printf("input string : %s\n", input_text);
    printf("input txt length : %d\n", strlen(input_text));
    /*
    else
    {
        memcpy(&tmp_text, raw_text, 8);
    }
    */

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
    #endif
    return 0;
}