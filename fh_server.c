// Taylor Koch
// CSCE 4050
// Project 1

// This is the server program for project 1

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define BUFFERSIZE 512
#define FILENAME "recieved.txt"
#define SERVER_IP "127.0.0.1"
#define PORT 4243

static int sv[2];

// returns encrypted string
const char * encrypt_string(char buffer[1024])
{
    char commandString[256];
    
    sprintf(commandString, "encrypt_string %s", buffer);
    
    write(sv[0], commandString, strlen(commandString));
    printf("Parent: Sent %s\n", commandString);
    read(sv[0], buffer, 1024);
    
    return buffer;
}

int main ()
{	
	pid_t pid;
    
    
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		perror("socketpair");
		exit(1);
	}
    
	if ((pid = fork()) < 0)
	{
		perror("fork");
		exit(1);
	}
    
	/* parent process (front end). is sv[0] */
	if (pid > 0)
	{
		int server_sockfd, client_sockfd;
		int server_size, client_size;
		int bytes_received;
		struct sockaddr_in server_address;
		struct sockaddr_in client_address;
		char message[BUFFERSIZE];
		FILE *fp;
        
		close(sv[1]);

		// create a TCP socket 
		server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

		// assign an IP address and port number to the socket
		server_address.sin_family = AF_INET;
		server_address.sin_addr.s_addr = inet_addr(SERVER_IP);
		server_address.sin_port = htons(PORT);
		server_size = sizeof(server_address);

		if (bind(server_sockfd, (struct sockaddr *) &server_address, server_size) < 0)
		{
			perror("bind");
			exit(1);
		}

		// begin listening on the socket
		if (listen(server_sockfd, 5) < 0)
		{
			perror("listen");
			exit(1);
		}

		client_size = sizeof(client_address);

		printf("Server is running\n"
			"IP address: %s\n"
			"Port:       %d\n\n"
			, SERVER_IP, PORT);
               
		// accept a connection on the socket
		client_sockfd = accept(server_sockfd, (struct sockaddr *) &client_address, &client_size);

		// if connection failed
		if (client_sockfd < 0)
		{
			perror("accept");
			exit(1);
		}

		printf("Connected to a client at %s\n", inet_ntoa(client_address.sin_addr));

		while (1)
		{
			fp = fopen(FILENAME, "w");
			if (fp == NULL) 
			{
				printf("File not found!\n");
				return 0;
			}
			else 
			{
				printf("Found file %s\n", FILENAME);
			}

			printf("Waiting for a messsage...\n\n");
            
			// get the message
			bytes_received = recv(client_sockfd, message, BUFFERSIZE, 0);
            
			if (bytes_received < 0)
			{
				perror("recv");
				exit(1);
			}
            
			message[bytes_received] = '\0';

			printf("Received message: '%s'\n", message);
            
			// break when client sends "exit"
			if (strncmp(message, "exit", 4) == 0)
				break;

			if(strncmp(message, "Encrypt", 7) == 0)
			{
				// Time to Receive the File
				while (1)
				{
					int n = 0;
					bzero(message,BUFFERSIZE);
					n = read(client_sockfd,message,BUFFERSIZE);
					if (n < 0) error("ERROR reading from socket");

					printf("%s %d", message, n);

					n = fwrite(message, sizeof(char), n, fp);
					if (n < 0) error("ERROR writing in file");

					if(n < BUFFERSIZE)
						break;
				}
			}
			else if(strncmp(message, "Decrypt", 7) == 0)
			{
				// Time to Receive the File
				while (1)
				{
					int n = 0;
					bzero(message,BUFFERSIZE);
					n = read(client_sockfd,message,BUFFERSIZE);
					if (n < 0) error("ERROR reading from socket");

					if(n < BUFFERSIZE)
						break;

					n = fwrite(message, 1, n, fp);
					if (n < 0) error("ERROR writing in file");
				}
			}

			printf("Recieved File\n");
			fclose(fp);
			fp = fopen(FILENAME, "r");

			//const char * ct = encrypt_string(message);
            
			//printf("Resulting ciphertext: %s\n", ct);
            
			// send cipher text to client
			while (1) 
			{
				// Read data into buffer.  We may not have enough to fill up buffer, so we
				// store how many bytes were actually read in bytes_read.
				int bytes_read = fread(message, sizeof(char), BUFFERSIZE, fp);
				if (bytes_read == 0) // We're done reading from the file
					break;

				printf("%s", message);

				if (bytes_read < 0) 
				{
					error("ERROR reading from file"); 
				}

				// You need a loop for the write, because not all of the data may be written
				// in one call; write will return how many bytes were written. p keeps
				// track of where in the buffer we are, while we decrement bytes_read
				// to keep track of how many bytes are left to write.
				void *p = message;
				while (bytes_read > 0) 
				{
					int bytes_written = write(client_sockfd, message, bytes_read);
					if (bytes_written <= 0) 
					{
						error("ERROR writing to socket\n");
					}
					bytes_read -= bytes_written;
					p += bytes_written;
				}
			}

			printf("Sent ciphertext to client\n\n");
		}
        
		close(client_sockfd);
		close(server_sockfd);
	}
	else    /* child process (secure environment). owns sv[1] */
	{
		char buffer[128];
		int bytesRead;
		char opensslCommand[BUFFERSIZE];
		char cipherText[BUFFERSIZE];
		FILE * fp;
        
		// close parent end
		close(sv[0]);
    
		for (;;)
		{
			// wait for a command
			printf("child: waiting for command\n");
			bytesRead = read(sv[1], buffer, 127);
			buffer[bytesRead] = '\0';
			printf("child: received command %s\n", buffer);
            
			// get the command
			char *chPtr = strchr(buffer, ' ');
			*chPtr = 0;
			chPtr++;
            
			if (strcmp("encrypt_string", buffer) == 0)
			{
				printf("Child: Encryption Requested\n");
				printf("Encrypting string '%s'\n", chPtr);
                
                
				// form the openssl command
				sprintf(opensslCommand, "echo '%s' | openssl enc -aes-128-cbc -nosalt -base64 -k MyPassword", chPtr);
				printf("child: calling '%s'\n", opensslCommand);
				// execute the openssl command and capture the output
				fp = popen(opensslCommand, "r");
				fgets(cipherText, sizeof(cipherText), fp);
				cipherText[strlen(cipherText) - 1] = '\0';
                
				// send the parent the result
				write(sv[1], cipherText, strlen(cipherText));
				printf("child: Wrote %s\n", cipherText);
			}
			else
				printf("whoops\n");
		}
	}
}