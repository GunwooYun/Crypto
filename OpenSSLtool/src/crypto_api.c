#include "../inc/crypto_api.h"

#if 0
U2 encrypt_RSAES_OAEP(IN U1 *rsa_key, IN U1 *plain, IN U4 plain_len, OUT U1 * cipher, OUT U4 *cipher_len)
{
	//int ret = 0;
	RSA *rsa = NULL;
	BIO *bio = BIO_new_mem_buf(rsa_key, -1);
	if(!bio)
	{
		printf("Failed bio\n");
		return 0x0f00;
	}
	rsa = PEM_read_bio_RSA_PUBKEY(bio, &rsa, NULL, NULL);
	if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
	*cipher_len = RSA_public_encrypt(plain_len, plain, cipher, rsa, RSA_PKCS1_OAEP_PADDING);
	printf("cipher length : %d\n", (unsigned int)*cipher_len);
	BIO_free_all(bio);
	RSA_free(rsa);
	if(cipher_len == 0) return 0x0f00;
	else return 0x9000;

}
#endif

U2 encrypt_RSAES_OAEP(IN RSA *rsa_key, IN U1 *plain, IN U4 plain_len, OUT U1 * cipher, OUT U4 *cipher_len)
{
	//int ret = 0;
	*cipher_len = RSA_public_encrypt(plain_len, plain, cipher, rsa_key, RSA_PKCS1_OAEP_PADDING);
	//printf("cipher length : %d\n", (unsigned int)*cipher_len);
	if(cipher_len == 0) return 0x0f00;
	else return 0x9000;

}

U2 decrypt_RSAES_OAEP(IN RSA *rsa_key, IN U1 *cipher, IN U4 cipher_len, OUT U1 *plain, OUT U4 *plain_len)
{
	//int ret = 0;
	*plain_len = RSA_private_decrypt(cipher_len, cipher, plain, rsa_key, RSA_PKCS1_OAEP_PADDING);
	if(plain_len == 0) return 0x0f00;
	else return 0x9000;

}

U2 GenRsaKey(IN U4 key_len, OUT RSA **rsa_key, OUT U1 *pub_key, OUT U1 *pri_key)
{
	int ret = 0;
	BIGNUM *bn = BN_new();
	if(!bn) HandleErrors(); 
	BN_set_word(bn, RSA_F4); // RSA_F4 : 65,537(dec)
	RSA *rsa = RSA_new();
	if(!rsa) HandleErrors();
	if(!RSA_generate_key_ex(rsa, key_len, bn, NULL)) // key length : 1024 bit
		HandleErrors();

	*rsa_key = rsa;

	BIO *bio_public  = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey (bio_public, rsa);
    BIO *bio_private = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL);

	int pub_len = BIO_pending(bio_public);
	int pri_len = BIO_pending(bio_private);

	//printf("public length : %d, private length : %d\n", pub_len, pri_len);

	//U1 *pub_key_buf = (U1 *)malloc(pub_len + 1);
	//U1 *pri_key_buf = (U1 *)malloc(pri_len + 1);
	U1 *pub_key_buf = (U1 *)malloc(pub_len);
	U1 *pri_key_buf = (U1 *)malloc(pri_len);

    BIO_read(bio_public, pub_key_buf, pub_len);
	BIO_read(bio_private, pri_key_buf, pri_len);   //now we read the BIO into a buffer

	//pri_key_buf[pri_len] = '\0';
    //pub_key_buf[pub_len] = '\0';

	memcpy(pub_key, pub_key_buf, pub_len);
	memcpy(pri_key, pri_key_buf, pri_len);

	//printf("\n%s\n:\n%s\n", pri_key_buf, pub_key_buf);fflush(stdout);  //now we print the keys

	free(pub_key_buf);
	free(pri_key_buf);

	BIO_free_all(bio_public);
	BIO_free_all(bio_private);

	BN_free(bn);

	//RSA_free(rsa);
#if 0
	BIGNUM *n = rsa->n;

	U1 *pubKey = (U1 *)malloc(4096);
	U1 *priKey = (U1 *)malloc(4096);
	memset(pubKey, 0, 4096);
	BIO pubBio = BIO_new_fp(pubKey, BIO_CLOSE);

	EVP_PKEY_print_private(pubBio, pkey, 0, NULL);

	printf("%s\n", pubKey);

	RSA *rsa_key = NULL;
	EVP_PKEY *pkey = NULL;
	BIO *out = NULL;
	BIGNUM *bne;

	// For print RSA key pair
	out = BIO_new_fp(stdout, BIO_CLOSE);

	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, rsa);
	if(pkey->type == EVP_PKEY_RSA)
	{
		RSA *x = pkey->pkey.rsa;
		bne = x->n;
	}


	// EVP_PKEY_print_private(out, pkey, 0, NULL);
	// EVP_PKEY_print_public(out, pkey, 0, NULL);


	//int buf_len = BN_num_bytes(bn);
	//printf("buf_len : %d\n", buf_len);


	char *pem_key;
	int keylen;

	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

	keylen = BIO_pending(bio);
	printf("keylen : %d\n", keylen);
	pem_key = calloc(keylen+1, 1); /* Null-terminate */
	BIO_read(bio, pem_key, keylen);

	printf("%s", pem_key);

	BIO_free_all(bio);
	//printf("generate key ret : %d\n", ret);

	/*
	if(!RSA_generate_key_ex(rsa, int bits, BIGNUM *e, BN_GENCB *cb))
		HandleErrors();
		*/
	free(pem_key);
#endif 
//	BN_free(bn);
//	RSA_free(rsa);
}

U2 GenCtrDRBG(IN U4 req_rand_len, OUT U1 *out_rand)
{
	RAND_DRBG *drbg = NULL;
	U1 rand_buf[1024] = {0x00, };
	U1 seed[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	drbg = RAND_DRBG_new(NID_aes_128_ctr, RAND_DRBG_FLAG_CTR_NO_DF, NULL);
	if(drbg == NULL)
	{
		printf("Failed to DRBG new\n");
		return 1;
	}

	if(!RAND_DRBG_instantiate(drbg, seed, sizeof(seed)))
		HandleErrors();

	if(!RAND_DRBG_generate(drbg, rand_buf, req_rand_len, 0, NULL, 0))
		HandleErrors();

	memcpy(out_rand, rand_buf, req_rand_len);

	RAND_DRBG_free(drbg);

	return 0x9000;
}

U2 GenKey(IN U4 req_key_len, OUT U1 *key)
{
	U2 ret = 0;

	U1 key_buf[1024] = {0x00, };

	ret = GenCtrDRBG(req_key_len, key_buf);
	
	memcpy(key, key_buf, req_key_len);
	
	return 0x9000;
}

U2 Sha256(IN U1 *msg, IN U4 msg_len, OUT U1 *md)
{
	SHA256_CTX ctx;

	if(!SHA256_Init(&ctx))
		HandleErrors();

	if(!SHA256_Update(&ctx, msg, msg_len))
		HandleErrors();

	if(!SHA256_Final(md, &ctx))
		HandleErrors();

	return 0x9000;
}
U2 HmacSha256(IN U1 *key, IN U4 key_len, IN U1 *msg, IN U4 msg_len, OUT U1 *md, OUT U4 *md_len)
{
	int ret = 0;
	HMAC_CTX *ctx = HMAC_CTX_new();
	if(!ctx){
		printf("HMAC_CTX_new() is NULL\n");
		return 0xffff;
	}

	if(!HMAC_Init_ex(ctx, key, (int)key_len, EVP_sha256(), NULL))
		HandleErrors();

	if(!HMAC_Update(ctx, msg, (size_t)msg_len))
		HandleErrors();

	if(!HMAC_Final(ctx, md, md_len))
		HandleErrors();

	HMAC_CTX_free(ctx);

	return 0x9000;
}

U2 GmacGetTag(IN U1 *key, IN U1 *iv, IN U4 iv_len, IN U1 *aad, IN U4 aad_len, IN U4 req_tag_len, OUT U1 *tag, OUT U4 *tag_len)
{
	U4 outl = 0;

	/* variable for TAG */
	U1 tag_buf[17] = {0, };

	EVP_CIPHER_CTX *ctx = NULL;

    if((ctx = EVP_CIPHER_CTX_new()) == NULL)
	{
		printf("[FAIL] EVP_CIPHER_CTX_new\n");
		return 0x0f00;
	}

	/* Tag length should be in the range below */
	if(req_tag_len > 16 || req_tag_len < 12){
		printf("required tag length wrong\n");
		return 1;
	}

	/* Set cipher type and mode */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
		HandleErrors();
    }

    /* Set IV length if length is not 96 bit */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL)) {
		HandleErrors();
    }

    /* Initialise key and IV */
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
		HandleErrors();
    }
	// printf("iv length : %d\n", EVP_CIPHER_CTX_iv_length(ctx));

    /* Zero or more calls to specify any AAD */
    if (!EVP_EncryptUpdate(ctx, NULL, &outl, aad, aad_len)) {
		HandleErrors();
    }

    /* Finalise: note get no output for GMAC */
    if (!EVP_EncryptFinal_ex(ctx, tag_buf, &outl)) {
		HandleErrors();
    }

	memset(tag_buf, 0, sizeof(tag_buf));

	/* Get tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, req_tag_len, tag_buf)) {
		HandleErrors();
    }

	memcpy(tag, tag_buf, req_tag_len);

	return SUCCESS;

}

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
        return 1;
    }

    /* Encryption INIT */
    if(!EVP_EncryptInit(ctx, evp_cipher, key, iv))
		HandleErrors();

	if(block_mode == MODE_GCM)
	{
		/* Tag length should be in the range below */
		if(req_tag_len > 16 || req_tag_len < 12){
			printf("required tag length wrong\n");
			return 1;
		}

		if(!EVP_EncryptUpdate(ctx, NULL, (int *)&outl, (const unsigned char*)aad, aad_len))
			HandleErrors();
		outl = 0; // init 0 for update
	}

	if((padding_flag == NONE_PADDING_BLOCK) && (((int)plain_len % EVP_CIPHER_CTX_block_size(ctx)) != 0))
	{
		printf("None padding mode failed => Check plain length (NOT multiple of block)\n");
		return 1;
	}

    if(!EVP_CIPHER_CTX_set_padding(ctx, padding_flag))
		HandleErrors();

	/* Expand length of cipher buffer for padding */
    cipher_buf_len = plain_len + EVP_CIPHER_CTX_block_size(ctx);

    cipher_buf = (U1 *)malloc(cipher_buf_len);
    if(cipher_buf == NULL)
    {
        printf("cipher buf malloc failed\n");
        return 1;
    }

    if(!EVP_EncryptUpdate(ctx, &cipher_buf[outl], &nBytesWritten, plain_text, plain_len))
		HandleErrors();
    outl += nBytesWritten;

    if(!EVP_EncryptFinal(ctx, &cipher_buf[outl], &nBytesWritten))
		HandleErrors();
    outl += nBytesWritten;

    memcpy(cipher, cipher_buf, outl);
    *cipher_len = outl;

	if (block_mode == MODE_GCM)
	{
		if(!EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_GET_TAG, (int)req_tag_len, (unsigned char *)tag_buf))
		HandleErrors();

		tag_buf_len = strlen(tag_buf);
		memcpy(tag, tag_buf, tag_buf_len);
		*tag_len = tag_buf_len;
	}

	free(cipher_buf);
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
	U1 *plain_buf = NULL;

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
        printf("evp_cipher_dec OR evp_ctx_dec is NULL\n");
        return 0xffff;
    }

    /* Encryption INIT */
    if(!EVP_DecryptInit(ctx, evp_cipher, key, iv))
		HandleErrors();

	if(block_mode == MODE_GCM)
    {
        ret = EVP_DecryptUpdate(ctx, NULL, (int *)&outl, (const unsigned char*)aad, aad_len);
        if(!ret)
        {
            printf("EVP_EncryptUpdate aad ERROR\n");
            return 0xffff;
        }
		outl = 0; // Init 0 for update
    }

	if((padding_flag == NONE_PADDING_BLOCK) && (((int)cipher_len % EVP_CIPHER_CTX_block_size(ctx)) != 0))
	{
		printf("None padding mode failed => Check plain length (NOT multiple of block)\n");
		return 1;
	}

    if(!EVP_CIPHER_CTX_set_padding(ctx, padding_flag))
		HandleErrors();

    plain_buf_len = cipher_len + EVP_CIPHER_CTX_block_size(ctx);
	plain_buf = (U1 *)malloc(sizeof(U1) * plain_buf_len);

    if(!EVP_DecryptUpdate(ctx, &plain_buf[outl], &nBytesWritten, cipher_text, cipher_len))
		HandleErrors();
    outl += nBytesWritten;

	if(block_mode == MODE_GCM)
	{
		if(!EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (unsigned char *)tag))
			HandleErrors();
	}

	ret = EVP_DecryptFinal(ctx, &plain[outl], &nBytesWritten);

	memcpy(plain, plain_buf, outl);
	free(plain_buf);
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		outl += nBytesWritten;
		*plain_len = outl;

		return SUCCESS;
	}
	else
	{
		printf("Tag is NOT same\n");
		HandleErrors();
	}
}
