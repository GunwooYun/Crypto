#include "../inc/system.h"

extern U1 KEK[32];

U1 systemKey[16] = {0x64,0x62,0x73,0x72,0x6A,0x73,0x64,0x6E,0x61,0x6A,0x74,0x77,0x6F,0x64,0x64,0x6C};
U1 flag_need_init = 0;
U1 flag_logged_in = 0;
bool flag_system_verified = false;

char getKey(void)
{
    char ch;
    struct termios old;
    struct termios current;

    /* 현재 설정된 terminal i/o 값을 backup함 */
    tcgetattr(0, &old);

    /* 현재의 설정된 terminal i/o에 일부 속성만 변경하기 위해 복사함 */
    current = old;

    /* buffer i/o를 중단함 */
    current.c_lflag &= ~ICANON;

#if 0
    if (is_echo) {  // 입력값을 화면에 표시할 경우
        current.c_lflag |= ECHO;
    } else {        // 입력값을 화면에 표시하지 않을 경우
        current.c_lflag &= ~ECHO;
    }
#endif

    current.c_lflag &= ~ECHO;

    /* 변경된 설정값으로 설정합니다.*/
    tcsetattr(0, TCSANOW, &current);
    ch = getchar();
    tcsetattr(0, TCSANOW, &old);

    return ch;
}

U2 Hmac(IN U1 *key, IN U1 *msg, IN U4 msg_len, OUT U1 *md, OUT U4 *md_len)
{
    int ret = 0;

    HMAC_CTX *ctx = HMAC_CTX_new();
    if(!ctx){
        printf("HMAC_CTX_new() is NULL\n");
        return 1;
    }

    if(!HMAC_Init_ex(ctx, key, 16, EVP_sha256(), NULL))
        HandleErrors();

    if(!HMAC_Update(ctx, msg, (size_t)msg_len))
        HandleErrors();

    if(!HMAC_Final(ctx, md, md_len))
        HandleErrors();

    HMAC_CTX_free(ctx);

    return 0;
}

int arrcmp(IN U1 *arr_a, IN U1 *arr_b, IN U4 len)
{
    U1 *p_a = arr_a;
    U1 *p_b = arr_b;
    for(int i = 0; i < len; i++)
    {
        if(*(p_a++) != *(p_b++))
            return 1;
    }
    return 0;
}

int getStrLen(U1 *str, U4 strSize)
{
    U1 *pStr = str;
    int cnt = 0;
    while(cnt < strSize)
    {
        if(*pStr == '\n')
        {
            *pStr = 0;
            break;
        }
        cnt++;
        pStr++;
        if(cnt >= strSize)
        {
            while(getchar() != '\n');
            break;
        }
    }
    /*
    while((*(pStr++) != '\n'))
    {
        if(cnt >= (strSize-1))
        {
            while(getchar() != '\n');
            break;
        }
        cnt++;
    }
    */
    return cnt;
}

int verifyData()
{
	FILE *fp_data = NULL;
	FILE *fp_system = NULL;

	U4 fileSize = 0;
	U4 readFileBytes = 0;
	U4 writtenFileBytes = 0;

	U1 checkedDigest[32] = {0x00, };
	U4 checkedDigestLen = 0;

	U1 savedDigest[32] = {0x00, };

	U2 ret = 0;

	/* Read data from .data and Get Hmac */
	fp_data = fopen("./.data", "rb");
	if(fp_data == NULL)
		return 1;

	fseek(fp_data, 0, SEEK_END);
	fileSize = ftell(fp_data);

	U1 *fileBuffer = (U1 *)malloc(fileSize);

	fseek(fp_data, 0, SEEK_SET);

	readFileBytes = fread(fileBuffer, fileSize, 1, fp_data);

	Hmac(systemKey, fileBuffer, readFileBytes, checkedDigest, &checkedDigestLen);

	fp_system = fopen("./.system", "rb");
	if(fp_system == NULL)
	{
		// Doesn't exist .system file, so create
		fp_system = fopen("./.system", "wb");
		if(fp_system == NULL)
		{
			printf("file open failure\n");
			return 1;
		}

		// Create .system file
		writtenFileBytes = fwrite(checkedDigest, 32, 1, fp_system);
#ifdef DEBUG_MODE
		assert(writtenFileBytes == 1);
#endif
		goto end;
	}
	else
	{
		// .system file already exists
		fseek(fp_system, 0, SEEK_SET);
		readFileBytes = fread(savedDigest, 32, 1, fp_system);
		assert(readFileBytes == 1);
	}
	ret = arrcmp(checkedDigest, savedDigest, 32);
	if(ret > 0)
	{
		printf("system file verification failed\n");
		return 1;
	}

	flag_system_verified = true;

end:
	free(fileBuffer);
	fclose(fp_data);
	fclose(fp_system);

	return 0;

}

void init_data()
{
	FILE *fp_data = NULL;
	U1 id_buf[32] = {0, };
	U1 hashed_id[32] = {0, };
	U1 pw_buf[32] = {0, };
	U1 re_pw_buf[32] = {0, };
	U1 salt[32] = {0, };
	const U1 salt_len = 32;
	U1 salted_pw[64] = {0, };
	U1 hashed_pw[32] = {0, };
	U4 writtenBytes = 0;

	char key;
	int buf_idx = 0;

	int loginStep = CHECK_ID;
	bool isLoggedIn = false;

	int ret = 0;

	/* First Execution */
	fp_data = fopen("./.data", "rb");
	if(fp_data != NULL)
	{
		fclose(fp_data);
		ret = verifyData();
		goto finishVerify;
	}

	printf("Initialize Data\n");
	printf("Create ID & Password\n");

	while(!isLoggedIn)
	{
		buf_idx = 0;
		switch(loginStep)
		{
			case CHECK_ID:
				memset(id_buf, 0, sizeof(id_buf));
				printf("ID (len : 5 ~ 20) : ");
				while((key = getchar()) != '\n')
				{
					if(buf_idx < 32)
					{
						id_buf[buf_idx++] = key;
					}
				}
#ifdef DEBUG_MODE
				printf("Number of typed keys : %d\n", buf_idx);
				printf("typed id : ");
				for(int i = 0; i < 32; i++)
				{
					printf("%x ", id_buf[i]);
				}
				printf("\n");
#endif
				if(buf_idx >= 5 && buf_idx <= 20) loginStep = CHECK_PW;
				else printf("id length incorrect\n");
				break;
			case CHECK_PW:
				memset(pw_buf, 0, sizeof(pw_buf));
				buf_idx = 0;
				printf("PW (len : 5 ~ 30) : ");
				while((key = getKey()) != '\n')
				{
					if(buf_idx < 32)
					{
						pw_buf[buf_idx++] = key;
					}
				}
				printf("\n");
#ifdef DEBUG_MODE
				printf("Number of typed keys : %d\n", buf_idx);
				printf("typed password : ");
				for(int i = 0; i < 32; i++)
				{
					printf("%x ", pw_buf[i]);
				}
				printf("\n");
#endif
				if(buf_idx >= 5 && buf_idx <= 30) loginStep = CHECK_RE_PW;
				else printf("password length incorrect\n");
				break;
			case CHECK_RE_PW:
				memset(re_pw_buf, 0, 32);
				buf_idx = 0;
				printf("Re type PW  (len : 5 ~ 30) : ");
				while((key = getKey()) != '\n')
				{
					if(buf_idx < 32)
					{
						re_pw_buf[buf_idx++] = key;
					}
				}
				printf("\n");
#ifdef DEBUG_MODE
				printf("Number of typed keys : %d\n", buf_idx);
				printf("re-typed password : ");
				for(int i = 0; i < 32; i++)
				{
					printf("%x ", re_pw_buf[i]);
				}
				printf("\n");
#endif
				if(buf_idx >= 5 && buf_idx <= 30)
				{
					if(!strcmp(pw_buf, re_pw_buf))
					{
						isLoggedIn = true;
						break;
					}
					else
					{
						printf("re password not same\n");
					}
				}
				else
				{
					printf("password length incorrect\n");
				}
				break;
		}
	}

	/* Generate salt (len : 32byte) */
	GenCtrDRBG(salt_len, salt);

	/* | salt (16byte) | password (32byte) | salt (16byte) | */
	memcpy(salted_pw, salt, sizeof(salt) / 2);
	memcpy(salted_pw + (sizeof(salt) / 2), pw_buf, sizeof(pw_buf));
	memcpy(salted_pw + (sizeof(salt) / 2) + sizeof(pw_buf), salt + sizeof(salt) / 2, sizeof(salt) / 2);

	/* Execute SHA-256 for ID */
	Sha256(id_buf, sizeof(id_buf), hashed_id);
#ifdef DEBUG_MODE
	printf("hashed id : ");
	for(int i = 0; i < 32; i++)
	{
		printf("%#x ", hashed_id[i]);
	}
	printf("\n");
#endif

	/* Execute SHA-256 for pw */
	Sha256(salted_pw, sizeof(salted_pw), hashed_pw);
#ifdef DEBUG_MODE
	printf("hashed pw : ");
	for(int i = 0; i < 32; i++)
	{
		printf("%#x ", hashed_pw[i]);
	}
	printf("\n");
#endif

	fp_data = fopen("./.data", "wb");
	if(fp_data == NULL)
	{
		printf("file open failure\n");
		return;
	}

	/* Write hashed id 32bytes */
	writtenBytes = fwrite(hashed_id, sizeof(U1) /* 1byte */, sizeof(hashed_id), fp_data);
	assert(writtenBytes == 32);

	 /* Write hashed pw 32bytes */
    writtenBytes = fwrite(hashed_pw, sizeof(U1) /* 1byte */, sizeof(hashed_pw), fp_data);
    assert(writtenBytes == 32);


    /* Write salt 32bytes */
    writtenBytes = fwrite(salt, sizeof(U1) /* 1byte */, sizeof(salt), fp_data);
    assert(writtenBytes == 32);

	fclose(fp_data);

	ret = verifyData();
finishVerify:
	if (ret == 0)
	{
		if(flag_system_verified)
			printf("Data file verified\n");
		else
			printf("HMAC Generated\n");
		return;
	}
	else
	{
		printf("verify error\n");
		exit(0);
	}

}

void log_in()
{
	U1 saved_hashed_id[32] = {0, };
	U1 saved_hashed_pw[32] = {0, };
	U1 id_buf[32] = {0, };
	U1 pw_buf[32] = {0, };
	U1 input_hashed_id[32] = {0, };
	U1 input_hashed_pw[32] = {0, };
	U1 salt[32] = {0, };
	U1 salted_pw[64] = {0, };
	U4 readBytes = 0;

	U4 bufLen = 0;

	bool loginLoop = true;
	U1 flag_id_passed = 0;

	FILE *fp_data = NULL;

	char key = 0;
	int buf_idx = 0;

	fp_data = fopen("./.data", "rb");
	if(fp_data == NULL)
	{
		init_data();
		return;
	}

	/* Fetch ID, PW, salt from data file */
	readBytes = fread(saved_hashed_id, sizeof(U1), 32, fp_data); // fetch id
	assert(readBytes == 32);
	readBytes = fread(saved_hashed_pw, sizeof(U1), 32, fp_data); // fetch pw
	assert(readBytes == 32);
#ifdef DEBUG_MODE
	for(int i = 0; i < 32; i++)
	{
		printf("%x ", saved_hashed_pw[i]);
	}
	printf("\n");
#endif
	readBytes = fread(salt, sizeof(U1), 32, fp_data); // fetch salt
	assert(readBytes == 32);


	printf("*** Log in ***\n");
	while(loginLoop)
	{
		switch(flag_id_passed)
		{
			case 0 :
				memset(id_buf, 0, sizeof(id_buf));
				printf("ID (len : 5 ~ 20) : ");
				fgets(id_buf, sizeof(id_buf), stdin);

				bufLen = getStrLen(id_buf, 32);
				if(bufLen < 5 || bufLen > 20)
				{
					printf("id length incorrect\n");
					break;
				}

				/* Get hashed input ID */
				Sha256(id_buf, sizeof(id_buf), input_hashed_id);

				if(!arrcmp(input_hashed_id, saved_hashed_id, 32))
				{
					flag_id_passed = 1;
				}
				break;

			case 1 :
				memset(pw_buf, 0, sizeof(pw_buf));
				buf_idx = 0;
				printf("PW (len : 5 ~ 30) : ");
				while((key = getKey()) != '\n')
				{
					if(buf_idx < 32)
					{
						pw_buf[buf_idx++] = key;
					}
				}
				if( buf_idx >= 5 && buf_idx <= 30) {}
				else
				{
					printf("Password Length Incorrect\n");
					continue;
				}
				//fgets(pw_buf, sizeof(pw_buf), stdin);

				//bufLen = getStrLen(pw_buf, 32);
				/*
				   if(bufLen < 5 || bufLen > 20)
				   {
				   printf("pw length incorrect\n");
				   break;
				   }
				 */
#ifdef DEBUG_MODE
				printf("login pw buf : ");
				for(int i = 0; i < 32; i++)
				{
					printf("%x ", pw_buf[i]);
				}
				printf("\n");
#endif
				memset(salted_pw, 0, sizeof(salted_pw));
				memset(input_hashed_pw, 0, sizeof(input_hashed_pw));

				/* | salt (16byte) | password (32byte) | salt (16byte) | */
				memcpy(salted_pw, salt, sizeof(salt) / 2);
				memcpy(salted_pw + (sizeof(salt) / 2), pw_buf, sizeof(pw_buf));
				memcpy(salted_pw + (sizeof(salt) / 2) + sizeof(pw_buf), salt + sizeof(salt) / 2, sizeof(salt) / 2);

				/* Get hashed input password */
				Sha256(salted_pw, sizeof(salted_pw), input_hashed_pw);

#ifdef DEBUG_MODE
				printf("input hashed password : ");
				for(int i = 0; i < 32; i++)
				{
					printf("%x ", input_hashed_pw[i]);
				}
				printf("\n");
#endif

				if(!arrcmp(input_hashed_pw, saved_hashed_pw, 32))
				{
					loginLoop = false;
				}
				else
				{
					printf("password not correct!\n");
				}
				break;
		}
	}

	/* Iterate hash 1000 times*/
	for(int i = 0; i < 1000; i++)
	{
		Sha256(input_hashed_pw, sizeof(input_hashed_pw), input_hashed_pw);
	}

	/* Generate KEK using SHA-256 */
	memset(KEK, 0, sizeof(KEK));
	Sha256(input_hashed_pw, sizeof(input_hashed_pw), KEK);

	fclose(fp_data);
	printf("\n\nLog-in Success\n");

}

int showMenu(void)
{
	int menu, ret = 0;
	int symKeyIdx, symKeyLen;
	printf("1. Generate Symmetric Key\n");
	printf("2. Generate RSA Key\n");
	printf("0. Exit\n");
	printf("\n");
	printf("Choose Menu (1~5) >> ");

	scanf("%d", &menu);

	switch(menu)
	{
		case EXIT:
			return 0;
		case GEN_SYM_KEY:
			printf("Choose Index (0~4) >> ");
			scanf("%d", &symKeyIdx);
			printf("Length (16, 24, 32) >> ");
			scanf("%d", &symKeyLen);
			ret = genSymmKey(symKeyIdx, symKeyLen);
			if(ret == 0)
				printf("Generated Symmetric Key Successfully!\n");
			break;
		case GEN_RSA_KEY:
			break;
		case ENC_DEC_ARIA:
			break;
		default :
			break;
	}
	
}

void start(void)
{
	while(1)
	{
		showMenu();
	}
}
