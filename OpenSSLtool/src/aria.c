#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "../inc/aria.h"
#include "../inc/defines.h"
#include "../inc/err.h"

U2 EncryptARIA(IN U1 *key, IN U1 padding_flag, IN U1 block_mode, IN U1 *plain_text, IN U4 plain_len, OUT U1 *cipher, OUT U4 *cipher_len, IN U1 req_tag_len, OUT U1 *tag, OUT U4 *tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad)
{
	U2 ret = 0;
	U4 outl = 0;
	EVP_CIPHER_CTX *ctx = NULL;
	U1 str_block_mode[12] = {0x00, };

    U1 *cipher_buf = NULL;
    U4 cipher_buf_len = 0;
    int nBytesWritten = 0;

	/* variable for TAG */
	U4 tag_buf_len = 0;
	U1 tag_buf[17] = {0, };


    U4 key_len = 16;

    switch(block_mode)
    {
        case MODE_ECB :
            sprintf(str_block_mode, "aria-%d-ecb", key_len*8);
            break;
        case MODE_CBC :
            sprintf(str_block_mode, "aria-%d-cbc", key_len*8);
            break;
        case MODE_CTR :
            sprintf(str_block_mode, "aria-%d-ctr", key_len*8);
            break;
        case MODE_GCM :
            sprintf(str_block_mode, "aria-%d-gcm", key_len*8);
            break;
        default :
            break;
    }

    const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname(str_block_mode);
    ctx = EVP_CIPHER_CTX_new();

    if((evp_cipher == NULL) || (ctx == NULL))
    {
        printf("evp_cipher_enc OR evp_ctx_enc is NULL\n");
        return 0xffff;
    }

    /* Encryption INIT */
    ret = EVP_EncryptInit(ctx, evp_cipher, key, iv);
    if(!ret)
    {
        printf("EVP_EncryptInit_ex ERROR\n");
        return 0xffff;
    }

	if(block_mode == MODE_GCM)
	{
		/* Tag length should be in the range below */
		if(req_tag_len > 16 || req_tag_len < 12){
			printf("required tag length wrong\n");
			return 0xffff;
		}

		ret = EVP_EncryptUpdate(ctx, NULL, (int *)&outl, (const unsigned char*)aad, aad_len);
		outl = 0; // init 0 for update
		if(!ret)
		{
			printf("Encrypt Init for GCM ERROR\n");
			return 0xffff;
		}
	}

    ret = EVP_CIPHER_CTX_set_padding(ctx, padding_flag);
    if(!ret)
    {
        printf("EVP_CIPHER_CTX_set_padding ERROR\n");
        return 0xffff;
    }

	/* Expand length of cipher buffer for padding */
    cipher_buf_len = plain_len + EVP_CIPHER_CTX_block_size(ctx);

    cipher_buf = (U1 *)malloc(cipher_buf_len);
    if(cipher_buf == NULL)
    {
        printf("cipher buf malloc failed\n");
        return 0xffff;
    }

    EVP_EncryptUpdate(ctx, &cipher_buf[outl], &nBytesWritten, plain_text, plain_len);
    outl += nBytesWritten;

    EVP_EncryptFinal(ctx, &cipher_buf[outl], &nBytesWritten);
    outl += nBytesWritten;

    memcpy(cipher, cipher_buf, outl);
	//cipher = cipher_buf;
    *cipher_len = outl;

	if (block_mode == MODE_GCM)
	{
		ret = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_GET_TAG, (int)req_tag_len, (unsigned char *)tag_buf);
		if(!ret)
		{
			printf("EVP_CIPHER_CTX_ctrl ERROR\n");
			return 0xffff;
		}

		tag_buf_len = strlen(tag_buf);
		memcpy(tag, tag_buf, tag_buf_len);
		*tag_len = tag_buf_len;
	}
	EVP_CIPHER_CTX_free(ctx);
}


U2 DecryptARIA(IN U1 *key, IN U1 padding_flag, IN U1 block_mode, IN U1 *cipher_text, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len, IN U1 *tag, IN U1 tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad)
{
	U2 ret = 0;
	U4 outl = 0;
	EVP_CIPHER_CTX *ctx = NULL;
	U1 str_block_mode[12] = {0x00, };

    int nBytesWritten = 0;

    U4 plain_buf_len = 0;

    U4 key_len = 16;

	U1 plain_buf[128] = {0x00, };


    switch(block_mode)
    {
        case MODE_ECB :
            sprintf(str_block_mode, "aria-%d-ecb", key_len*8);
            break;
        case MODE_CBC :
            sprintf(str_block_mode, "aria-%d-cbc", key_len*8);
            break;
        case MODE_CTR :
            sprintf(str_block_mode, "aria-%d-ctr", key_len*8);
            break;
        case MODE_GCM :
            sprintf(str_block_mode, "aria-%d-gcm", key_len*8);
            break;
        default :
            break;
    }

    const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname(str_block_mode);
    ctx = EVP_CIPHER_CTX_new();

    if((evp_cipher == NULL) || (ctx == NULL))
    {
        printf("evp_cipher_dec OR evp_ctx_dec is NULL\n");
        return 0xffff;
    }

    /* Encryption INIT */
    ret = EVP_DecryptInit(ctx, evp_cipher, key, iv);
    if(!ret)
    {
        printf("EVP_DecryptInit_ex ERROR\n");
        return 0xffff;
    }

	if(block_mode == MODE_GCM)
    {
        ret = EVP_DecryptUpdate(ctx, NULL, (int *)&outl, (const unsigned char*)aad, aad_len);
        if(!ret)
        {
            printf("EVP_EncryptUpdate aad ERROR\n");
            return 0xffff;
        }
		outl = 0; // Init 0 for updatte
    }

    ret = EVP_CIPHER_CTX_set_padding(ctx, padding_flag);
    if(!ret)
    {
        printf("EVP_CIPHER_CTX_set_padding ERROR\n");
        return 0xffff;
    }

    EVP_DecryptUpdate(ctx, &plain[outl], &nBytesWritten, cipher_text, cipher_len);
    outl += nBytesWritten;

	if(block_mode == MODE_GCM)
	{
		ret = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (unsigned char *)tag);
		if(!ret)
		{
			printf("dec SET TAG ERROR\n");
			return 0xffff;
		}
	}


	ret = EVP_DecryptFinal(ctx, &plain[outl], &nBytesWritten);
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		outl += nBytesWritten;
		*plain_len = outl;

		return SUCCESS;
	}
	else
		return 0xFFFF;
}

#if 0
U2 ARIA_Enc_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad)
{
    U4 key_len = 16;
    U2 ret = 0;
	U4 outl = 0;

    memset(cipher_type, 0, 12);

    switch(block_mode)
    {
        case MODE_ECB :
            sprintf(cipher_type, "aria-%d-ecb", key_len*8);
            break;
        case MODE_CBC :
            sprintf(cipher_type, "aria-%d-cbc", key_len*8);
            break;
        case MODE_CTR :
            sprintf(cipher_type, "aria-%d-ctr", key_len*8);
            break;
        case MODE_GCM :
            sprintf(cipher_type, "aria-%d-gcm", key_len*8);
            break;
        default :
            break;
    }

    const EVP_CIPHER *evp_cipher_enc = EVP_get_cipherbyname(cipher_type);
    evp_ctx_enc = EVP_CIPHER_CTX_new();

    if((evp_cipher_enc == NULL) || (evp_ctx_enc == NULL))
    {
        printf("evp_cipher_enc OR evp_ctx_enc is NULL\n");
        return 0xffff;
    }

    /* Encryption INIT */
    ret = EVP_EncryptInit(evp_ctx_enc, evp_cipher_enc, key, iv);
    if(!ret)
    {
        printf("EVP_EncryptInit_ex ERROR\n");
        return 0xffff;
    }

	if(block_mode == MODE_GCM)
    {
        ret = EVP_EncryptUpdate(evp_ctx_enc, NULL, (int *)&outl, (const unsigned char*)aad, aad_len);
        if(!ret)
        {
            printf("Encrypt Init for GCM ERROR\n");
            return 0xffff;
        }
    }

    return 0x9000;
}

U2 ARIA_Enc_Update(IN U1 padding_flag, IN U1 block_mode, IN U1 *plain_text, IN U4 plain_len,  OUT U1 *cipher, OUT U4 *cipher_len, IN U1 req_tag_len, OUT U1 *tag, OUT U4 *tag_len)
{
    U2 ret = 0x0000;
    U4 outl = 0;
    U1 *cipher_buf = NULL;
    U4 cipher_buf_len = 0;
    int nBytesWritten = 0;
	//U4 req_tag_len = 14;

	/* variable for TAG */
	U4 tag_buf_len = 0;
	U1 tag_buf[17] = {0, };

	if(req_tag_len > 16 || req_tag_len < 12){
        printf("required tag length wrong\n");
        return 0xffff;
    }

    ret = EVP_CIPHER_CTX_set_padding(evp_ctx_enc, padding_flag);
    if(!ret)
    {
        printf("EVP_CIPHER_CTX_set_padding ERROR\n");
        return 0xffff;
    }

    cipher_buf_len = plain_len + EVP_CIPHER_CTX_block_size(evp_ctx_enc);

    cipher_buf = (U1 *)malloc(cipher_buf_len);
    if(cipher_buf == NULL)
    {
        printf("cipher buf malloc failed\n");
        return 0xffff;
    }

    EVP_EncryptUpdate(evp_ctx_enc, &cipher_buf[outl], &nBytesWritten, plain_text, plain_len);
    outl += nBytesWritten;

    EVP_EncryptFinal(evp_ctx_enc, &cipher_buf[outl], &nBytesWritten);
    outl += nBytesWritten;

    memcpy(cipher, cipher_buf, outl);
    *cipher_len = outl;

	if ( block_mode == MODE_GCM)
	{
		ret = EVP_CIPHER_CTX_ctrl (evp_ctx_enc, EVP_CTRL_AEAD_GET_TAG, (int)req_tag_len, (unsigned char *)tag_buf);
		if(!ret)
		{
			printf("EVP_CIPHER_CTX_ctrl ERROR\n");
			return 0xffff;
		}

		tag_buf_len = strlen(tag_buf);
		memcpy(tag, tag_buf, tag_buf_len);
		*tag_len = tag_buf_len;
	}

    free(cipher_buf);

    return 0x9000;
}

U2 ARIA_Dec_Init(IN U1 *key, IN U1 block_mode, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad)
{
    U4 key_len = 16;
    //U1 cipher_type[12] = {0x00, };
    U2 ret = 0x0000;
	U4 outl = 0;

    memset(cipher_type, 0, 12);

    switch(block_mode)
    {
        case MODE_ECB :
            sprintf(cipher_type, "aria-%d-ecb", key_len*8);
            break;
        case MODE_CBC :
            sprintf(cipher_type, "aria-%d-cbc", key_len*8);
            break;
        case MODE_CTR :
            sprintf(cipher_type, "aria-%d-ctr", key_len*8);
            break;
        case MODE_GCM :
            sprintf(cipher_type, "aria-%d-gcm", key_len*8);
            break;
        default :
            break;
    }

    const EVP_CIPHER *evp_cipher_dec = EVP_get_cipherbyname(cipher_type);
    evp_ctx_dec = EVP_CIPHER_CTX_new();

    if((evp_cipher_dec == NULL) || (evp_ctx_dec == NULL))
    {
        printf("evp_cipher_dec OR evp_ctx_dec is NULL\n");
        return 0xffff;
    }

    /* Encryption INIT */
    ret = EVP_DecryptInit(evp_ctx_dec, evp_cipher_dec, key, iv);
    if(!ret)
    {
        printf("EVP_DecryptInit_ex ERROR\n");
        return 0xffff;
    }

	if(block_mode == MODE_GCM)
    {
        ret = EVP_DecryptUpdate(evp_ctx_dec, NULL, (int *)&outl, (const unsigned char*)aad, aad_len);
        if(!ret)
        {
            printf("EVP_EncryptUpdate aad ERROR\n");
            return 0xffff;
        }
    }
    return 0x9000;
}

U2 ARIA_Dec_Update(IN U1 padding_flag, IN U1 *cipher_text, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len, IN U1 *tag, IN U1 tag_len)
{
    U2 ret = 0;
    U4 outl = 0;
    U4 plain_buf_len = 0;
    int nBytesWritten = 0;
    ret = EVP_CIPHER_CTX_set_padding(evp_ctx_dec, padding_flag);
    if(!ret)
    {
        printf("EVP_CIPHER_CTX_set_padding ERROR\n");
        return 0xffff;
    }

    EVP_DecryptUpdate(evp_ctx_dec, &plain[outl], &nBytesWritten, cipher_text, cipher_len);
    outl += nBytesWritten;

	ret = EVP_CIPHER_CTX_ctrl (evp_ctx_dec, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (unsigned char *)tag);
    if(!ret)
    {
        printf("dec SET TAG ERROR\n");
        return 0xffff;
    }


	ret = EVP_DecryptFinal(evp_ctx_dec, &plain[outl], &nBytesWritten);
	if(ret > 0)
	{
		outl += nBytesWritten;
		*plain_len = outl;

		return SUCCESS;
	}
	else
		return 0xFFFF;
}
#endif
