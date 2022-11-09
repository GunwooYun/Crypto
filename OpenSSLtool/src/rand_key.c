/*
    printf("Generate key -->\t");

    U1 *key = (U1 *)malloc(EVP_CIPHER_CTX_key_length(ctx_enc));
    if(key == NULL)
    {
        printf("malloc for key failed \n");
        ret = 0x0fa0;
        return ret;
    }
    ret = RAND_bytes(key,EVP_CIPHER_CTX_key_length(ctx_enc));
    if(!ret)
    {
        printf("RAND_bytes ERROR\n");
        ret = 0x0fc1;
        return ret;
    }
    printf("okay\n");
    */
