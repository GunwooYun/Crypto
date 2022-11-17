#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aria.h>

int main(int argc, char *argv[])
{
	unsigned char plain_data[256];
	unsigned char hash_data[256];
	int plain_data_len;
	int i;

	memset(plain_data, 0x00, sizeof(plain_data));
	memset(hash_data, 0x00, sizeof(hash_data));
	sprintf(plain_data, "vnVXSNnmHnmxAIneIbjEuLWgQbdASwtDUqXIVdcMLeRGHfpJjePLjuxeBd");
//	sprintf(plain_data, "Hello, world");
	plain_data_len = strlen(plain_data);
	sha256(plain_data, plain_data_len, hash_data);
	fprintf(stdout, "<message>\n");
	fprintf(stdout, "%.*s\n", plain_data_len, plain_data);
	fprintf(stdout, "<hash value>\n");
	for( i = 0; i < strlen(hash_data); i++ )
	{
		fprintf(stdout, "%02x", hash_data[i]);
	}
	fprintf(stdout, "\n");

	memset(plain_data, 0x00, sizeof(plain_data));
	memset(hash_data, 0x00, sizeof(hash_data));
	sprintf(plain_data, "VnVXSNnmHnmxAIneIbjEuLWgQbdASwtDUqXIVdcMLeRGHfpJjePLjuxeBd");
	//sprintf(plain_data, "vnVXSNnCjuErOsdWxLqzxALGgNsnBzVJwILKkgEDlwGiJLjysktInJjSztbYhFRfdZyZdsyVSLpfxxVovcAaalFZdVpcBOkyLoBZiYgoPEkhskVdLSaatErzEkWmqObbYGFKeTcOpIPpXbYvgWJYpGYHXWXigQQvzgpbwKoFkOrkKVDbBQdTtMUQXNNFjXsRrvfLTLWayTCxmHnmxAIneIbjEuLWgQbdASwtDUqXIVdcMLeRGHfpJjePLjuxeBd");
	plain_data_len = strlen(plain_data);
	sha256(plain_data, plain_data_len, hash_data);
	fprintf(stdout, "<message>\n");
	fprintf(stdout, "%.*s\n", plain_data_len, plain_data);
	fprintf(stdout, "<hash value>\n");
	for( i = 0; i < strlen(hash_data); i++ )
	{
		fprintf(stdout, "%02x", hash_data[i]);
	}
	fprintf(stdout, "\n");

	return 1;
}
int sha256(unsigned char *plain_data, int plain_data_len, unsigned char *hash_data)
{
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, plain_data, plain_data_len);
	SHA256_Final(hash_data, &sha256);
	//printf("length : %ld\n", strlen(hash_data));

	return 1;
}
