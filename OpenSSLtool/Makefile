main : main.o hmac.o
	gcc -o main main.o hmac.o -I/usr/local/ssl/include -I/home/gwyun/Workplace/Crypto/OpenSSLtool/inc -L/usr/local/ssl/lib -lcrypto -lssl
main.o : main.c
	gcc -c -o main.o main.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
hmac.o : ./src/hmac.c
	gcc -c -o hmac.o ./src/hmac.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
clean:
	rm -rf main main.o hmac.o
