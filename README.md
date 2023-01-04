# Crypto Tool using OpenSSL
### Application implemented of crypto algorithm (ARIA, AES, RSA ..)
## Development Environment
* Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-53-generic x86_64)
* OpenSSL 1.1.1s
* GCC 11.3.0
* GNU Make 4.3
## Development History
* 22.12.12 (Mon) Fixed saved wrong hashed password
* 22.12.12 (Mon) Make range of ID (5byte ~ 20byte)
* 22.12.21 (Wed) Hide typed keys for password, Changed structure of init_data()
* 22.12.25 (Sun) Add function of verify data file using HMAC
* 22.12.26 (Mon) Make typed password hidden for login and fix some errors
* 22.12.30 (Fir) Separate initialzie data & login & verify function in file (system.h, system.c)
* 22.12.31 (Sat) Create menu and generate symmetric key
* 23.01.04 (Wed) Make function ARIA
