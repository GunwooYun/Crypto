CC = gcc
TARGET = main
OBJS = main.o crypto_api.o err.o

$(TARGET) : $(OBJS)
	$(CC) -o main main.o crypto_api.o err.o -I/usr/local/ssl/include -I/home/gwyun/Workplace/Crypto/OpenSSLtool/inc -L/usr/local/ssl/lib -lcrypto -lssl
main.o : main.c
	$(CC) -c -o main.o main.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
crypto_api.o : ./src/crypto_api.c
	$(CC) -c -o crypto_api.o ./src/crypto_api.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
err.o : ./src/err.c
	$(CC) -c -o err.o ./src/err.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
clean:
	rm -rf main main.o hmac.o aria.o err.o crypto_api.o
