main : main.o crypto_api.o err.o
	gcc -o main main.o crypto_api.o err.o -I/usr/local/ssl/include -I/home/gwyun/Workplace/Crypto/OpenSSLtool/inc -L/usr/local/ssl/lib -lcrypto -lssl
#main : main.o hmac.o aria.o err.o
#	gcc -o main main.o hmac.o aria.o err.o -I/usr/local/ssl/include -I/home/gwyun/Workplace/Crypto/OpenSSLtool/inc -L/usr/local/ssl/lib -lcrypto -lssl
main.o : main.c
	gcc -c -o main.o main.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
#hmac.o : ./src/hmac.c
#	gcc -c -o hmac.o ./src/hmac.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
#aria.o : ./src/aria.c
#gcc -c -o aria.o ./src/aria.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
crypto_api.o : ./src/crypto_api.c
	gcc -c -o crypto_api.o ./src/crypto_api.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
err.o : ./src/err.c
	gcc -c -o err.o ./src/err.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
clean:
	rm -rf main main.o hmac.o aria.o err.o
