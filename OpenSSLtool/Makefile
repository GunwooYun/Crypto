CC = gcc
TARGET = main
OBJS = main.o example.o crypto_api.o system.o err.o

$(TARGET) : $(OBJS)
	$(CC) -g -o main main.o example.o crypto_api.o err.o system.o -I/usr/local/ssl/include -I/home/gwyun/Workplace/Crypto/OpenSSLtool/inc -L/usr/local/ssl/lib -lcrypto -lssl
main.o : main.c
	$(CC) -g -c -o main.o main.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
example.o : ./src/example.c
	$(CC) -g -c -o example.o ./src/example.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
crypto_api.o : ./src/crypto_api.c
	$(CC) -g -c -o crypto_api.o ./src/crypto_api.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
system.o : ./src/system.c
	$(CC) -g -c -o system.o ./src/system.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
err.o : ./src/err.c
	$(CC) -g -c -o err.o ./src/err.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
clean:
	rm -rf main main.o example.o hmac.o aria.o err.o crypto_api.o system.o .data .system
