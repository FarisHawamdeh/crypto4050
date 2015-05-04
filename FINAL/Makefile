all: SSL_server SSL_client

SSL_server: SSL-Server.c myAPI.c
	gcc -Wall -o ssl-server SSL-Server.c myAPI.c -L/usr/lib -lssl -lcrypto

SSL_client: SSL-Client.c 
	gcc -Wall -o ssl-client SSL-Client.c -L/usr/lib -lssl -lcrypto
