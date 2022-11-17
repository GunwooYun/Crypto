#include "../inc/err.h"
#include <stdio.h>

void DebugPrintArr(IN U1 *arr, IN U4 arr_len)
{
	for(int i = 0; i < arr_len; i++)
		printf("%#x ", arr[i]);
	printf("\n");
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
