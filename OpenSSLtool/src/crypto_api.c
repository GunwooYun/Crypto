#include "../inc/crypto_api.h"
#include <assert.h>

U1 KEK[32] = {0, };

U2 verify_ECDSA(EC_KEY *ec_key, IN U1 *msg, IN U4 msg_len, IN U1 *sign_R, IN U1 *sign_S)
{
	int ret;
	ECDSA_SIG *sig_rs = ECDSA_SIG_new();

	U1 md[32] = {0, };
	size_t md_len = 32;

	/* Hashing with SHA-256 */
	SHA256_CTX sha_256;
	if(!SHA256_Init(&sha_256)) HandleErrors();
	if(!SHA256_Update(&sha_256, msg, msg_len)) HandleErrors();
	if(!SHA256_Final(md, &sha_256)) HandleErrors();
	
	BIGNUM *sig_r = BN_bin2bn(sign_R, 32, NULL);
	BIGNUM *sig_s = BN_bin2bn(sign_S, 32, NULL);

	ret = ECDSA_SIG_set0(sig_rs, sig_r, sig_s);

	ret = ECDSA_do_verify(md, md_len, sig_rs, ec_key);
	ECDSA_SIG_free(sig_rs);

	if (ret < 0)
	{
		HandleErrors();
	}
	else if(ret == 0)
	{
		printf("No Verified\n");
		return 0x0f00;
	}
	else
	{
		printf("Verified\n");
		return 0x9000;
	}

}

U2 sign_ECDSA(EC_KEY *ec_key, IN U1 *msg, IN U4 msg_len, OUT U1 *sign_R, OUT U1 *sign_S)
{
	int ret;

	/* For SHA-256 */
	U1 md[32] = {0, };
	size_t md_len = 32;

	/* For ECDSA */
	ECDSA_SIG *sig_rs = ECDSA_SIG_new();
	U1 sig_r_buf[32], sig_s_buf[32];
	U4 sign_buf_len = 0, sig_r_len = 0, sig_s_len = 0;

	/* Hashing with SHA-256 */
	SHA256_CTX sha_256;
	if(!SHA256_Init(&sha_256)) HandleErrors();
	if(!SHA256_Update(&sha_256, msg, msg_len)) HandleErrors();
	if(!SHA256_Final(md, &sha_256)) HandleErrors();

	sig_rs = ECDSA_do_sign(md, md_len, ec_key);

	/* for old version */
	//sig_r = sig_rs->r;
	//sig_s = sig_rs->s;

	/* Get BIGNUM r,s from ECDSA_SIG */
	const BIGNUM *sig_r = ECDSA_SIG_get0_r(sig_rs);
	const BIGNUM *sig_s = ECDSA_SIG_get0_s(sig_rs);

	/* Get byte size of BIGNUM r, s */
	sig_r_len = BN_num_bytes(sig_r);
	sig_s_len = BN_num_bytes(sig_s);

	/* Convert BIGNUM r,s to unsigned char array */
	ret = BN_bn2bin(sig_r, sig_r_buf);
	ret = BN_bn2bin(sig_s, sig_s_buf);

	memcpy(sign_R, sig_r_buf, sig_r_len);
	memcpy(sign_S, sig_s_buf, sig_s_len);

	ECDSA_SIG_free(sig_rs);

	return 0x9000;
}

U2 Gen_EC_key(IN U4 std_curve, OUT EC_KEY **ec_key)
{
	EC_KEY *ecKey;

	ecKey = EC_KEY_new_by_curve_name(std_curve);
	if (ecKey == NULL)
	{
		printf("Create EC key failure\n");
		return 0x0f00;
	}
	if (!EC_KEY_generate_key(ecKey))
	{
		printf("Generate EC key failure\n");
		return 0x0f00;
	}

	*ec_key = ecKey;

	return 0x9000;
}

U2 verify_RSA_PSS(IN RSA *rsa_key, IN U1 *msg, IN U4 msg_len, IN U1 *sign, IN U4 sign_len)
{
	int ret;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;

	U1 md[32] = {0, };
	size_t md_len = 32;

	/* Hashing with SHA-256 */
	SHA256_CTX sha_256;
	if(!SHA256_Init(&sha_256)) HandleErrors();
	if(!SHA256_Update(&sha_256, msg, msg_len)) HandleErrors();
	if(!SHA256_Final(md, &sha_256)) HandleErrors();

	/* Convert RSA_key to EVP_PKEY */
	pkey = EVP_PKEY_new();
	if(pkey == NULL) HandleErrors();
	if(!EVP_PKEY_assign_RSA(pkey, rsa_key)) HandleErrors(); // RSA key assign to EVP_PKEY

	/* Perform Verify */
	ctx = EVP_PKEY_CTX_new(pkey, NULL /* No engine */);
	if(ctx == NULL) HandleErrors();
	if (EVP_PKEY_verify_init(ctx) <= 0) HandleErrors();
	/* Set padding PSS */
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) HandleErrors();
	/* Set Hash SHA-256 */
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) HandleErrors();

	ret = EVP_PKEY_verify(ctx, sign, (size_t)sign_len, md, md_len);

	if (ret == 1) printf("Verified\n");
	else printf("NO Verified\n");

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
}

U2 sign_RSA_PSS(IN RSA *rsa_key, IN U1 *msg, IN U4 msg_len, OUT U1 *sign, OUT U4 *sign_len)
{
	int ret;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;

	U1 md[32] = {0, }, *sign_buf;
	size_t sign_buf_len, md_len = 32;

	/* Hasing with SHA-256 */
	SHA256_CTX sha_256;
	if(!SHA256_Init(&sha_256)) HandleErrors();
	if(!SHA256_Update(&sha_256, msg, msg_len)) HandleErrors();
	if(!SHA256_Final(md, &sha_256)) HandleErrors();

	/* Convert RSA_key to EVP_PKEY */
	pkey = EVP_PKEY_new();
	if(pkey == NULL) HandleErrors();
	if(!EVP_PKEY_assign_RSA(pkey, rsa_key)) HandleErrors(); // RSA key assign to EVP_PKEY

	ctx = EVP_PKEY_CTX_new(pkey, NULL /* No engine */);
	if(ctx == NULL) HandleErrors();
	if (EVP_PKEY_sign_init(ctx) <= 0) HandleErrors();
	/* Set padding PSS */
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) HandleErrors();
	/* Set Hash SHA-256 */
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) HandleErrors();

	/* Determine buffer length */
	if (EVP_PKEY_sign(ctx, NULL, &sign_buf_len, md, md_len) <= 0) HandleErrors();

	sign_buf = OPENSSL_malloc(sign_buf_len);
	if(sign_buf == NULL){
		printf("malloc failure\n");
		return 0x0f00;
	}

	if (EVP_PKEY_sign(ctx, sign_buf, &sign_buf_len, md, md_len) <= 0) HandleErrors();

	memcpy(sign, sign_buf, sign_buf_len);
	*sign_len = sign_buf_len;

	OPENSSL_free(sign_buf);
	EVP_PKEY_CTX_free(ctx);
	//EVP_PKEY_free(pkey);
	//EVP_MD_CTX_free(md_ctx);
}

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

U2 GetKeyAriaAes(IN U1 key_idx, OUT U1 *key, OUT U4 *key_len)
{
	FILE *fp_data = NULL;

	U1 encKey_buf[32] = {0, };
	U4 encKey_buf_len = 0;
	U4 *pEncKey_buf_len = &encKey_buf_len;

	U1 key_buf[32] = {0, };
	U4 key_buf_len = 0;

	U2 ret = 0;
	int readBytes = 0;

	fp_data = fopen("./.data", "rb");
	if(fp_data == NULL)
	{
		PrintErrMsg(0xd284);
		return 0;
	}

	/* Read key length */
	ret = fseek(fp_data, KEY_LEN_FILE_OFFSET + key_idx, SEEK_SET);
	readBytes = fread(pEncKey_buf_len, sizeof(U1), 1, fp_data);


	if(readBytes != 0)
	{
		/* Read key */
		ret = fseek(fp_data, SYM_KEY_FILE_OFFSET + (32 * key_idx), SEEK_SET);
		readBytes = fread(encKey_buf, sizeof(U1), 32, fp_data);
		//assert((readBytes == 16) || (readBytes == 24) || (readBytes == 32));
		assert(readBytes == 32);
	}
	else
	{
		PrintErrMsg(0x003f);
		fclose(fp_data);
		return 0;
	}
	ret = DecryptKeyAriaCtr(KEK, encKey_buf, encKey_buf_len, key_buf, &key_buf_len);

	memcpy(key, key_buf, 32);
	*key_len = key_buf_len;

	fclose(fp_data);

	return 0x9000;
}

int GenKeyAriaAes(IN U1 key_idx, IN U4 req_key_len)
{
	U2 ret = 0;
	U1 tmp_buf[32] = {0, };
	U1 key_buf[32] = {0, };
	U4 readBytes = 0;
	U4 writtenBytes = 0;
	FILE *fp_data = NULL;

	U1 enc_key[32] = {0, };
	U4 enc_key_len = 0;

	/* Available index 0:4 */
	if (key_idx < 0 && key_idx > 4)
	{
		PrintErrMsg(0xfe03);
		return 0;
	}

	/* ARIA, AES key length : 16, 24, 32 byte */
	/*
	if ((req_key_len < 16) || ((req_key_len > 16) && (req_key_len < 24)) ||
			((req_key_len > 24) && (req_key_len < 32)) || (req_key_len > 32))
			*/
	if((req_key_len == 16) || (req_key_len == 24) || (req_key_len == 32)){}
	else
	{
		PrintErrMsg(0xfe04);
		return 0;
	}

	/* Generate key using CTR-DRBG */
	ret = GenCtrDRBG(req_key_len, key_buf);

	ret = EncryptKeyAriaCtr(KEK, key_buf, req_key_len, enc_key, &enc_key_len);

	fp_data = fopen("./.data", "r+b");
	if(fp_data == NULL)
	{
		PrintErrMsg(0xd284);
		return 0;
	}

	U4 *pEnc_key_len;
	pEnc_key_len = &enc_key_len;

	ret = fseek(fp_data, SYM_KEY_FILE_OFFSET +(32 * key_idx), SEEK_SET);
	readBytes = fread(tmp_buf, sizeof(U1), 32, fp_data);

	if(readBytes == 0)
	{
		/* Save key length */
		ret = fseek(fp_data, KEY_LEN_FILE_OFFSET + key_idx, SEEK_SET);
		writtenBytes = fwrite(pEnc_key_len, sizeof(U1), 1, fp_data);
		/* Save encrypted key */
		ret = fseek(fp_data, SYM_KEY_FILE_OFFSET + (32 * key_idx), SEEK_SET);
		writtenBytes = fwrite(enc_key, sizeof(U1), 32, fp_data);
		assert(writtenBytes == 32);
	}
	else
	{
		PrintErrMsg(0x003f);
		fclose(fp_data);
		return 0;
	}

	fclose(fp_data);
	
	return 1;
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


U2 EncryptKeyAriaCtr(IN U1 *kek, IN U1 *key, IN U4 key_len, OUT U1 *enc_key, OUT U4 *enc_key_len)
{
	U2 ret = 0;
	U4 outl = 0;
	U1 iv[] = { 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 }; // 16bytes
	EVP_CIPHER_CTX *ctx = NULL;

    U1 *enc_key_buf = NULL;
    // U4 enc_key_buf_len = plain_len; // if NOT padding
    int nBytesWritten = 0;

    const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname("aria-256-ctr"); // KEK len : 32byte
    ctx = EVP_CIPHER_CTX_new();

    if((evp_cipher == NULL) || (ctx == NULL))
    {
        printf("evp_cipher_enc OR evp_ctx_enc is NULL\n");
        return 1;
    }

    /* Encryption INIT */
    if(!EVP_EncryptInit(ctx, evp_cipher, kek, iv))
		HandleErrors();

    enc_key_buf = (U1 *)malloc(key_len);
    if(enc_key_buf == NULL)
    {
        printf("enc key buf malloc failed\n");
        return 1;
    }

    if(!EVP_EncryptUpdate(ctx, &enc_key_buf[outl], &nBytesWritten, key, key_len))
		HandleErrors();
    outl += nBytesWritten;

    if(!EVP_EncryptFinal(ctx, &enc_key_buf[outl], &nBytesWritten))
		HandleErrors();
    outl += nBytesWritten;

    memcpy(enc_key, enc_key_buf, outl);
    *enc_key_len = outl;

	free(enc_key_buf);
	EVP_CIPHER_CTX_free(ctx);
}

U2 DecryptKeyAriaCtr(IN U1 *kek, IN U1 *enc_key, IN U4 enc_key_len, OUT U1 *key, OUT U4 *key_len)
{
	U2 ret = 0;
	U4 outl = 0;
	EVP_CIPHER_CTX *ctx = NULL;

	U1 iv[] = { 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 }; // 16bytes

    int nBytesWritten = 0;

	U1 *key_buf = NULL;

    const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname("aria-128-ctr");
    ctx = EVP_CIPHER_CTX_new();

    if((evp_cipher == NULL) || (ctx == NULL))
    {
        printf("evp_cipher_dec OR evp_ctx_dec is NULL\n");
        return 0xffff;
    }

    /* Encryption INIT */
    if(!EVP_DecryptInit(ctx, evp_cipher, kek, iv))
		HandleErrors();

	key_buf = (U1 *)malloc(enc_key_len);
	if(key_buf == NULL)
	{
		printf("key buf malloc failed\n");
		return 1;
	}

	if(!EVP_DecryptUpdate(ctx, &key_buf[outl], &nBytesWritten, enc_key, enc_key_len))
		HandleErrors();
    outl += nBytesWritten;

	ret = EVP_DecryptFinal(ctx, &key_buf[outl], &nBytesWritten);
	outl += nBytesWritten;

	memcpy(key, key_buf, outl);
	*key_len = outl;

	free(key_buf);
	EVP_CIPHER_CTX_free(ctx);
}



U2 EncryptARIA(IN U1 key_idx, IN U1 padding_flag, IN U1 block_mode, IN U1 *plain_text, IN U4 plain_len, OUT U1 *cipher, OUT U4 *cipher_len, IN U1 req_tag_len, OUT U1 *tag, OUT U4 *tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad)
{
	U2 ret = 0;
	U4 outl = 0;
	EVP_CIPHER_CTX *ctx = NULL;
	U1 str_block_mode[12] = {0x00, };

	U1 *key = NULL;
	U4 key_len = 0;

    U1 *cipher_buf = NULL;
    U4 cipher_buf_len = 0;
    int nBytesWritten = 0;

	/* variable for TAG */
	U4 tag_buf_len = 0;
	U1 tag_buf[17] = {0, };


	/* Available index 0:4 */
	if (key_idx < 0 && key_idx > 4)
	{
		PrintErrMsg(0xfe03);
		return 0;
	}


	
	key = malloc(32);
	ret = GetKeyAriaAes(key_idx, key, &key_len);

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

	/* Expand length of cipher buffer for padding (ECB, CBC) */
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
		if(!EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_GET_TAG, req_tag_len, tag_buf))
		HandleErrors();

		tag_buf_len = strlen(tag_buf);
		memcpy(tag, tag_buf, tag_buf_len);
		*tag_len = tag_buf_len;
	}

	free(cipher_buf);
	free(key);
	EVP_CIPHER_CTX_free(ctx);
}

U2 DecryptARIA(IN U1 key_idx, IN U1 padding_flag, IN U1 block_mode, IN U1 *cipher, IN U4 cipher_len,  OUT U1 *plain, OUT U4 *plain_len, IN U1 *tag, IN U1 tag_len, IN U2 iv_len, IN U1 *iv, IN U2 aad_len, IN U1 *aad)
{
	U2 ret = 0;
	U4 out_len = 0;
	EVP_CIPHER_CTX *ctx = NULL;
	U1 str_block_mode[12] = {0x00, };

    int nBytesWritten = 0;

	U1 *key = NULL;
    U4 key_len = 0;

	/* Available index 0:4 */
	if (key_idx < 0 && key_idx > 4)
	{
		PrintErrMsg(0xfe03);
		return 0;
	}

	key = malloc(32);
	ret = GetKeyAriaAes(key_idx, key, &key_len);

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
    if(!(ctx = EVP_CIPHER_CTX_new()))
		HandleErrors();

    if((evp_cipher == NULL) || (ctx == NULL))
    {
        printf("evp_cipher_dec OR evp_ctx_dec is NULL\n");
        return 0xffff;
    }

    /* Decryption INIT */
    if(!EVP_DecryptInit(ctx, evp_cipher, key, iv))
		HandleErrors();


	if(block_mode == MODE_GCM)
	{
	
		if(!EVP_DecryptUpdate(ctx, NULL, (int *)&out_len, (const unsigned char*)aad, aad_len))
			HandleErrors();
		out_len = 0; // Init 0 for update
	}

	if((padding_flag == NONE_PADDING_BLOCK) && (((int)cipher_len % EVP_CIPHER_CTX_block_size(ctx)) != 0))
	{
		printf("None padding mode failed => Check plain length (NOT multiple of block)\n");
		return 1;
	}

    if(!EVP_CIPHER_CTX_set_padding(ctx, padding_flag))
		HandleErrors();

    if(!EVP_DecryptUpdate(ctx, plain, &nBytesWritten, cipher, cipher_len))
		HandleErrors();
    out_len += nBytesWritten;

	if(block_mode == MODE_GCM)
	{
		if(!EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (unsigned char *)tag))
			HandleErrors();
	}

	/*
	if(!(ret = EVP_DecryptFinal(ctx, plain + out_len, &nBytesWritten)))
		HandleErrors();
	*/
	ret = EVP_DecryptFinal(ctx, plain + out_len, &nBytesWritten);
	out_len += nBytesWritten;
	*plain_len = out_len;

	free(key);
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		return SUCCESS;
	}
	else
	{
		printf("Tag is NOT same\n");
		return 0x0fe3;
	}
}
