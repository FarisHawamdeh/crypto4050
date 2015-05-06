To compile:

SSL-server.c : gcc -Wall -o ssl-server SSL-Server.c -L/usr/lib -lssl -lcrypto
SSL-client.c : gcc -Wall -o ssl-client SSL-Client.c -L/usr/lib -lssl -lcrypto




To run:

Server: ./ssl-server <port>
    Ex. ./ssl-server 8080
    
Client: ./ssl-client localhost <port>
    ex. ./ssl-client localhost 8080
    
  

Referenced "http://simplestcodings.blogspot.com/2010/08/secure-server-client-using-openssl-in-c.html" for some of the SSL Sockets code.
