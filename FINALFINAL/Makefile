all: SSL_server SSL_client secure_server

SSL_server: SSL-Server.c myAPI.c
	gcc -Wall -o ssl-server SSL-Server.c myAPI.c -L/usr/lib -lssl -lcrypto

SSL_client: SSL-Client.c 
	gcc -Wall -o ssl-client SSL-Client.c -L/usr/lib -lssl -lcrypto

secure_server: secureServer.c
	gcc secureServer.c -0 secureserver
