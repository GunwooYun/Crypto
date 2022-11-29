#include "../inc/example.h"
#include <assert.h>

void testGmac(void)
{
	U2 ret;

    U1 iv[] = { 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 }; // 16bytes
    U1 aad[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };    // 16 Bytes

    U4 req_tag_len = 14;
    U1 tag[17] = {0x00, };
    U4 tag_len = 0;

    U1 key_index = 0x00;
    U1 *key = NULL;
    U4 key_len = 0;

    key = (U1 *)malloc(MAX_KEY_SIZE);
    if(key == NULL) assert(key == NULL);

    ret = GetKeyAriaAes(key_index, key, &key_len);

	ret = GmacGetTag(key, iv, sizeof(iv), aad, sizeof(aad), req_tag_len, tag, &tag_len);	
	DebugPrintArr(tag, req_tag_len);
}
void testDrbg(void)
{
	U2 ret;
	U1 key[16] = {0, };
	printf("******* DRBG TEST ************\n");
    ret = GenCtrDRBG(16, key);
    DebugPrintArr(key, 16);
}

void testRSA_sign_verify(void)
{
	U2 ret = 0;

    U1 msg[] = "Hello, world";
    U4 msg_len = sizeof(msg);

    U1 public_key[4096] = {0, };
    U1 private_key[4096] = {0, };

    U1 sign[32] = {0x00, };
    U4 sign_len = 0;

    RSA *rsa_key = NULL;
    ret = GenRsaKey(1024, &rsa_key, public_key, private_key);

    U1 * cipher = malloc(RSA_size(rsa_key));
    if(cipher == NULL) assert (cipher != NULL);

    printf("******* RSA-PSS Signification ************\n");
    ret = sign_RSA_PSS(rsa_key, msg, msg_len, sign, &sign_len);
    ret = verify_RSA_PSS(rsa_key, msg, msg_len, sign, sign_len);
}

void testRSA_enc_dec(void)
{
	U2 ret = 0;


    U1 msg[] = "Hello, world";
    U4 msg_len = sizeof(msg);
    //U1 ct[256 + 1] = {0, };
    U1 pt[4096] = {0, };

    U1 public_key[4096] = {0, };
    U1 private_key[4096] = {0, };


    RSA *rsa_key = NULL;
    ret = GenRsaKey(1024, &rsa_key, public_key, private_key);

    U1 * cipher = malloc(RSA_size(rsa_key));
    if(cipher == NULL) assert (cipher != NULL);
    U4 cipher_len = 0;

    printf("******* RSA Encryption ************\n");
    ret = encrypt_RSAES_OAEP(rsa_key, msg, sizeof(msg), cipher, &cipher_len);
    printf("cipher length : %d\n", cipher_len);

    DebugPrintArr(cipher, cipher_len);

    ret = decrypt_RSAES_OAEP(rsa_key, cipher, cipher_len, pt, &msg_len);

    ret = RSA_private_decrypt(cipher_len, cipher, pt, rsa_key, RSA_PKCS1_OAEP_PADDING);

    printf("%s\n", pt);
}

void testSha256(void)
{
    U1 msgDgst[3400] = {0x00, };
    U4 msgDgst_len = 0;
    U1 hmacData[30] = {"hello,world"};

	printf("******* SHA-256 TEST ************\n");
    DebugPrintArr(hmacData, (U4)strlen(hmacData));
    Sha256(hmacData, (U4)strlen(hmacData), msgDgst);
    DebugPrintArr(msgDgst, 32);
}

void testEcdsa(void)
{
	U1 ret = 0;

	U1 msg[] = "Hello, world";
    U4 msg_len = sizeof(msg);

    U1 sign_R[32] = {0, };
    U1 sign_S[32] = {0, };

	EC_KEY *ec_key = NULL;
    ret = Gen_EC_key(NID_secp256k1, &ec_key);

    printf("******* ECDSA Signification ************\n");
    ret = sign_ECDSA(ec_key, msg, msg_len, sign_R, sign_S);

    //DebugPrintArr(sign_R, 32);
    //DebugPrintArr(sign_S, 32);

    printf("******* ECDSA Verification ************\n");
    ret = verify_ECDSA(ec_key, msg, msg_len, sign_R, sign_S);
}

void testHmac(void)
{
	U1 ret = 0;
	printf("******* HMAC TEST ************\n");
    U1 msgDgst[3400] = {0x00, };
    U4 msgDgst_len = 0;
    U1 hmacData[30] = {"hello,world"};
    memset(msgDgst, 0, 3400);

    U1 key_index = 0x00;
    U1 *key = NULL;
    U4 key_len = 0;

    key = (U1 *)malloc(MAX_KEY_SIZE);
    if(key == NULL) assert(key == NULL);

    ret = GetKeyAriaAes(key_index, key, &key_len);

    DebugPrintArr(hmacData, (U4)strlen(hmacData));
    ret = HmacSha256(key, key_len, hmacData, (U4)strlen(hmacData), msgDgst, &msgDgst_len);
    DebugPrintArr(msgDgst, msgDgst_len);

    free(key);
}

void testAria(void)
{
    U2 ret = 0;
    const U4 plain_size = 155;

    const U1 iv[] = { 0x0f, 0x02, 0x05, 0x03, 0x08, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xda, 0xfb, 0xcc, 0xd0, 0xe0, 0xf0 }; // 16bytes
    const U1 aad[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };    // 16 Bytes

    U1 * plain = (U1 *)malloc(plain_size);
    U4 plain_len = 0;

    U1 * cipher = (U1 *)malloc(plain_size + ARIA_BLOCK_SIZE); // For padding
    U4 cipher_len = 0;

    U1 * dplain = (U1 *)malloc(plain_size);
    U4 dplain_len = 0;

    U4 req_tag_len = 14;
    U1 tag[17] = {0x00, };
    U4 tag_len = 0;

    U1 key_index = 0x00;
    U1 *key = NULL;
    U4 key_len = 0;

    key = (U1 *)malloc(MAX_KEY_SIZE);
    if(key == NULL) assert(key == NULL);

    /* Plain Text get random value */
    ret = RAND_bytes(plain, plain_size);
    if(!ret)
    {
        printf("Random Plain Text Failed\n");
        return;
    }

    printf("*************** ARIA TEST ****************\n");

    U1 mode = 0x00;
    U1 padding = 0x00;

    while(mode < 0x05)
    {
        memset(key, 0, MAX_KEY_SIZE);
        memset(cipher, 0, plain_size + ARIA_BLOCK_SIZE);
        memset(dplain, 0, plain_size);

		key_index = mode % 0x03;
        ret = GetKeyAriaAes(key_index, key, &key_len);

        switch(mode)
        {
            case MODE_ECB:
                printf("******* ARIA Encryption Start (ECB, padding) ************\n");
                printf("Key (length : %d bit) : ", key_len*8);
                DebugPrintArr(key, key_len);

                printf("Plain (length : %d)\n", plain_size);
                DebugPrintArr(plain, plain_size);

                ret = EncryptARIA(key_index, PADDING_BLOCK, mode, plain, plain_size, cipher, &cipher_len, req_tag_len, tag, &tag_len, sizeof(iv), iv, sizeof(aad), aad);
                printf("cipher (length : %d)\n", cipher_len);
                DebugPrintArr(cipher, cipher_len);

                printf("******* ARIA Decryption Start (ECB, padding) ************\n");
                ret =  DecryptARIA(key_index, PADDING_BLOCK, mode, cipher, cipher_len, dplain, &dplain_len, tag, tag_len, sizeof(iv), iv, sizeof(aad), aad);
                printf("Plain (length : %d)\n", dplain_len);
                DebugPrintArr(dplain, dplain_len);
                printf("\n\n");
                break;

            case MODE_CBC:
                printf("******* ARIA Encryption Start (CBC, padding) ************\n");
                printf("Key (length : %d bit) : ", key_len*8);
                DebugPrintArr(key, key_len);

                printf("Plain (length : %d)\n", plain_size);
                DebugPrintArr(plain, plain_size);

                ret = EncryptARIA(key_index, PADDING_BLOCK, mode, plain, plain_size, cipher, &cipher_len, req_tag_len, tag, &tag_len, sizeof(iv), iv, sizeof(aad), aad);
                printf("cipher (length : %d)\n", cipher_len);
                DebugPrintArr(cipher, cipher_len);

                printf("******* ARIA Decryption Start (CBC, padding) ************\n");
                ret =  DecryptARIA(key_index, PADDING_BLOCK, mode, cipher, cipher_len, dplain, &dplain_len, tag, tag_len, sizeof(iv), iv, sizeof(aad), aad);
                printf("Plain (length : %d)\n", dplain_len);
                DebugPrintArr(dplain, dplain_len);
                printf("\n\n");
                break;
            case MODE_CTR:
                printf("******* ARIA Encryption Start (CTR, no padding) ************\n");
                printf("Key (length : %d bit) : ", key_len*8);
                DebugPrintArr(key, key_len);
				printf("Plain (length : %d)\n", plain_size);
                DebugPrintArr(plain, plain_size);

                ret = EncryptARIA(key_index, PADDING_BLOCK, mode, plain, plain_size, cipher, &cipher_len, req_tag_len, tag, &tag_len, sizeof(iv), iv, sizeof(aad), aad);
                printf("cipher (length : %d)\n", cipher_len);
                DebugPrintArr(cipher, cipher_len);

                printf("******* ARIA Decryption Start (CTR, no padding) ************\n");
                ret =  DecryptARIA(key_index, PADDING_BLOCK, mode, cipher, cipher_len, dplain, &dplain_len, tag, tag_len, sizeof(iv), iv, sizeof(aad), aad);
                printf("Plain (length : %d)\n", dplain_len);
                DebugPrintArr(dplain, dplain_len);
                printf("\n\n");
                break;
            case MODE_GCM:
                printf("******* ARIA Encryption Start (GCM, no padding) ************\n");
                printf("Key (length : %d bit) : ", key_len*8);
                DebugPrintArr(key, key_len);

                printf("Plain (length : %d)\n", plain_size);
                DebugPrintArr(plain, plain_size);

                ret = EncryptARIA(key_index, PADDING_BLOCK, mode, plain, plain_size, cipher, &cipher_len, req_tag_len, tag, &tag_len, sizeof(iv), iv, sizeof(aad), aad);
                printf("cipher (length : %d)\n", cipher_len);
                DebugPrintArr(cipher, cipher_len);

                printf("******* ARIA Decryption Start (GCM, no padding) ************\n");
                ret =  DecryptARIA(key_index, PADDING_BLOCK, mode, cipher, cipher_len, dplain, &dplain_len, tag, tag_len, sizeof(iv), iv, sizeof(aad), aad);
                printf("Plain (length : %d)\n", dplain_len);
                DebugPrintArr(dplain, dplain_len);
                ret == 1 ? printf("\nTag authorization ok\n") : printf("\nTag authorization fail\n");
                printf("\n\n");
                break;
            default:
                break;
        }

        mode++;
    }

    free(key);
    free(plain);
    free(cipher);
}
