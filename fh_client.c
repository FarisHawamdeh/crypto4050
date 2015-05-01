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
#define PORT 4244

int main ()
{
	int sockfd;
	struct sockaddr_in address;
	char message[BUFFERSIZE];
	char ciphertext[BUFFERSIZE];
	FILE *fp;

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
			printf("Encrypt or Decrypt: ", SERVER_IP);
			fgets(message, BUFFERSIZE, stdin);
		
			// remove newline
			message[strlen(message) - 1] = '\0';
		} while (strlen(message) <= 0);

		if(strncmp(message, "Encrypt", 7) == 0)
		{
			if (write(sockfd, message, strlen(message)) < 0)
			{
				perror("write");
				exit(1);
			}
		
			printf("\nSent '%s'\n\n", message, SERVER_IP);

			do
			{
				printf("Enter FileName To Encrypt: ", SERVER_IP);
				fgets(message, BUFFERSIZE, stdin);
		
				// remove newline
				message[strlen(message) - 1] = '\0';
			} while (strlen(message) <= 0);

			fp = fopen(message, "r+");

			if (fp == NULL) 
			{
				printf("File not found!\n");
				continue;
			}
			else 
			{
				printf("Found file %s\n", message);
			}
		}
		else if(strncmp(message, "Decrypt", 7) == 0)
      {
			if (write(sockfd, message, strlen(message)) < 0)
			{
				perror("write");
				exit(1);
			}
		
			printf("\nSent '%s'\n\n", message, SERVER_IP);

			do
			{
				printf("Enter FileName To Decrypt: ", SERVER_IP);
				fgets(message, BUFFERSIZE, stdin);
		
				// remove newline
				message[strlen(message) - 1] = '\0';
			} while (strlen(message) <= 0);

			fp = fopen(message, "r+");

			if (fp == NULL) 
			{
				printf("File not found!\n");
				continue;
			}
			else 
			{
				printf("Found file %s\n", message);
			}
      }

		// break when user enters "exit"
		if (strncmp(message, "exit", 4) == 0) 
		{
			if (write(sockfd, message, strlen(message)) < 0)
			{
				perror("write");
				exit(1);
			}

			printf("\nSent '%s'\n\n", message, SERVER_IP);

			break;
		}
		
		// Send The File
		while (1) 
		{
			// Read data into buffer.  We may not have enough to fill up buffer, so we
			// store how many bytes were actually read in bytes_read.
			int bytes_read = fread(message, sizeof(char),sizeof(message), fp);
			if (bytes_read == 0) // We're done reading from the file
				break;

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
				int bytes_written = write(sockfd, message, bytes_read);
				if (bytes_written <= 0) 
				{
					error("ERROR writing to socket\n");
				}
				bytes_read -= bytes_written;
				p += bytes_written;
			}
		}

		printf("File Sent\n");
		fclose(fp);
		
		fp = fopen("back.txt", "w");

		// Time to Receive the File
		while (1)
		{
			int n = 0;
			bzero(message,BUFFERSIZE);
			n = read(sockfd,message,BUFFERSIZE);
			if (n < 0) error("ERROR reading from socket");

			n = fwrite(message, 1, n, fp);
			if (n < 0) error("ERROR writing in file");

			if(n < BUFFERSIZE)
				break;
		}
		fclose(fp);

	}
	
	close (sockfd);
}
