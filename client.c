// Taylor Koch
// CSCE 4050
// Project 1

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define BUFFERSIZE 512
#define SERVER_IP "127.0.0.1"
#define PORT 4242

int main ()
{
	int sockfd;
	struct sockaddr_in address;
	char message[BUFFERSIZE];
	char ciphertext[BUFFERSIZE];

	// create a TCP socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		perror("socket");
		exit(1);
	}

	// create an address for the socket
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(SERVER_IP); // cse02
	address.sin_port = htons(PORT);

	// attempt to connect to server
	if (connect(sockfd, (struct sockaddr *) &address, sizeof(address)) < 0)
	{
		perror("connect");
		exit(1);
	}
	
	printf("\nConnected to server at %s\n\n", SERVER_IP);

	// send text until "exit" is sent
	while (1) 
	{
		do
		{
			printf("Enter text to send: ", SERVER_IP);
			fgets(message, BUFFERSIZE, stdin);
		
			// remove newline
			message[strlen(message) - 1] = '\0';
		} while (strlen(message) <= 0);
		
		if (write(sockfd, message, strlen(message)) < 0)
		{
			perror("write");
			exit(1);
		}
		
		printf("\nSent '%s'\n\n", message, SERVER_IP);
		
		// break when user enters "exit"
		if (strncmp(message, "exit", 4) == 0) 
			break;	
		
		if (recv(sockfd, ciphertext, BUFFERSIZE, 0) < 0)
		{
			perror("recv");
			exit(1);
		}
		printf("CipherText received from %s: %s\n\n", SERVER_IP, ciphertext);
	}
	
	close (sockfd);
}
