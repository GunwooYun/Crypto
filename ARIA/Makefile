main : main.o
	gcc -o main main.o -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
main.o : main.c
	gcc -c -o main.o main.c #-I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
clean:
	rm main
