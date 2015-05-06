#ifdef __APPLE__
#  define error printf
#endif

//SSL-Client.c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <string.h>



int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}		

int main(int count, char *strings[]){

		char buffer[128];
		int bytesRead, server;
		char *portnum;
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);


		if ( count != 2 )
    	{
        	printf("usage: %s <portnum>\n", strings[0]);
        	exit(0);
    	}
    	portnum=strings[1];

		server = OpenListener(atoi(portnum));
		int client = accept(server, (struct sockaddr*)&addr, &len); 

		while (1)
		{
			// wait for a command
			printf("child: waiting for command\n");
			bytesRead = read(client, buffer, 127);
			buffer[bytesRead] = '\0';
			printf("child: received command %s\n", buffer);

			printf("Buffer : %s\n", buffer);

			if (strcmp("exit", buffer) == 0)
				exit(0);

			
			if(strcmp("encrypt_file", buffer) == 0)
			{
				printf("Child: Encryption Requested\n");

				system("openssl enc -aes-128-cbc -salt -base64 -k MyPassword -in recieved.txt -out return.txt");
				write(client, "Success", strlen("Success"));

			}
			else if(strcmp("decrypt_file", buffer) == 0)
			{
				printf("Child: Encryption Requested\n");

				system("openssl enc -d -aes-128-cbc -salt -base64 -k MyPassword -in recieved.txt -out return.txt");
				write(client, "Success", strlen("Success"));

			}
			else
			{
				printf("whoops\n");
				write(client, "Success", strlen("Success"));
			}
		}
}
