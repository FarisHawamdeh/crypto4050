To compile:

SSL-server.c : gcc -Wall -o ssl-server SSL-Server.c -L/usr/lib -lssl -lcrypto
SSL-client.c : gcc -Wall -o ssl-client SSL-Client.c -L/usr/lib -lssl -lcrypto

