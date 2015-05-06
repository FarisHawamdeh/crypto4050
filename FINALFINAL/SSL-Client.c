#ifdef __APPLE__
#  define error printf
#endif

//SSL-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <error.h>

#define FAIL    -1
#define BUFFERSIZE 512
#define SERVER_IP "127.0.0.1"

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{   
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char *hostname, *portnum;
    char message[BUFFERSIZE];
    FILE *fp;

    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];

    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */

        while (1)
	{
		do
		{
			printf("Encrypt or Decrypt: ");
			fgets(message, BUFFERSIZE, stdin);
			// remove newline
			message[strlen(message) - 1] = '\0';
		} while (strlen(message) <= 0);

		if(strncmp(message, "Encrypt", 7) == 0)
		{
			if (SSL_write(ssl, message, strlen(message)) < 0)
			{
				perror("write");
				exit(1);
			}

			printf("\nSent '%s'\n\n", message);

			do
			{
				printf("Enter FileName To Encrypt: ");
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
			if (SSL_write(ssl, message, strlen(message)) < 0)
			{
				perror("write");
				exit(1);
			}

			printf("\nSent '%s'\n\n", message);

			do
			{
				printf("Enter FileName To Decrypt: ");
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
			if (SSL_write(ssl, message, strlen(message)) < 0)
			{
				perror("write");
				exit(1);
			}

			printf("\nSent '%s'\n\n", message);

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
				perror("ERROR reading from file");
			}

			// You need a loop for the write, because not all of the data may be written
			// in one call; write will return how many bytes were written. p keeps
			// track of where in the buffer we are, while we decrement bytes_read
			// to keep track of how many bytes are left to write.
			void *p = message;
			while (bytes_read > 0)
			{
				int bytes_written = SSL_write(ssl, message, bytes_read);
				if (bytes_written <= 0)
				{
					perror("ERROR writing to socket\n");
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
			n = SSL_read(ssl,message,BUFFERSIZE);
			if (n < 0) perror("ERROR reading from socket");

			n = fwrite(message, 1, n, fp);
			if (n < 0) perror("ERROR writing in file");

			if(n < BUFFERSIZE)
				break;
		}
		fclose(fp);

	}


        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
