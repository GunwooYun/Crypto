#include "../inc/err.h"
#include <stdio.h>

void DebugPrintArr(IN U1 *arr, IN U4 arr_len)
{
	for(int i = 0; i < arr_len-1; i++)
		printf("0x%02x,", arr[i]);
	printf("0x%02x\n", arr[arr_len-1]);
}
void DebugPrintLine(void)
{
	printf("------------- DEBUG LINE -------------\n");
}

void HandleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
void PrintErrMsg(U2 err_msg)
{
	printf("---error---\n");
}
