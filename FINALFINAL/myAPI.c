#ifdef __APPLE__
#  define error printf
#endif
#include "myAPI.h"

void myAPI_encrypt_file(int sock) {
	int message[512];
	write(sock, "encrypt_file", strlen("encrypt_file"));
    read(sock, message, 512);
}

void myAPI_decrypt_file(int sock) {
	int message[512];
	write(sock, "decrypt_file", strlen("decrypt_file"));
    read(sock, message, 512);
}