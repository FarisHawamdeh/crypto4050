#ifdef __APPLE__
#  define error printf
#endif
//SSL-Server.c
#include <errno.h>
#include <unistd.h>
#include <malloc/malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "myAPI.h"

#define FAIL    -1
#define BUFFERSIZE 512
#define FILENAME "recieved.txt"
#define RETURNNAME "return.txt"
static int sv[2];

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

SSL_CTX* InitServerCTX(void)
{   const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv3_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

void Servlet(SSL* ssl, int secureServer) /* Serve the connection -- threadable */
{   
    int sd;
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        pid_t pid;


	/*if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		perror("socketpair");
		exit(1);
	}*/

	/*if ((pid = fork()) < 0)
	{
		perror("fork");
		exit(1);
	}*/

	/* parent process (front end). is sv[0] */
	/*if (pid > 0)
	{*/
		int bytes_received;
		char message[BUFFERSIZE];
		FILE *fp;

		//close(sv[1]);

		while (1)
		{
			printf("Waiting for a message...\n\n");

			// get the message
			bytes_received = SSL_read(ssl, message, BUFFERSIZE);

			fp = fopen(FILENAME, "w");
			if (fp == NULL)
			{
				printf("File not found!\n");
				//return 0;
			}
			else
			{
				printf("Found file %s\n", FILENAME);
			}

			if (bytes_received < 0)
			{
				perror("recv");
				exit(1);
			}

			message[bytes_received] = '\0';

			printf("Received message: '%s'\n", message);

			// break when client sends "exit"
			if (strncmp(message, "exit", 4) == 0)
			{
    			write(secureServer, "exit", strlen("exit"));
				break;
			}

			if(strncmp(message, "Encrypt", 7) == 0)
			{
				// Time to Receive the File
				while (1)
				{
					int n = 0;
					bzero(message,BUFFERSIZE);
					n = SSL_read(ssl,message,BUFFERSIZE);
					if (n < 0) perror("ERROR reading from socket");

					n = fwrite(message, sizeof(char), n, fp);
					if (n < 0) perror("ERROR writing in file");

					if(n < BUFFERSIZE)
						break;
				}

				fclose(fp);

				myAPI_encrypt_file(secureServer);

    			
			}
			else if(strncmp(message, "Decrypt", 7) == 0)
			{
				// Time to Receive the File
				while (1)
				{
					int n = 0;
					bzero(message,BUFFERSIZE);
					n = SSL_read(ssl,message,BUFFERSIZE);
					if (n < 0) perror("ERROR reading from socket");

					n = fwrite(message, sizeof(char), n, fp);
					if (n < 0) perror("ERROR writing in file");

					if(n < BUFFERSIZE)
						break;
				}

				fclose(fp);
				
				myAPI_decrypt_file(secureServer);
			}

			printf("Recieved File\n");
			fp = fopen(RETURNNAME, "r");

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

			printf("Sent ciphertext to client\n\n");
		}

	}

    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

int main(int count, char *strings[])
{
    SSL_CTX *ctx;
    int server, secureServer;
    char *portnum, *secureHostName, *securePortNum;

    /*if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }*/
    if ( count != 4 )
    {
        printf("Usage: %s <portnum> <secureHostName> <securePortNum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();

    portnum = strings[1];

    secureHostName=strings[2];
    securePortNum=strings[3];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
    secureServer= OpenConnection(secureHostName, atoi(securePortNum));
    while (1)
    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl, secureServer);         /* service connection */
        break;
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
    return 0;
}
