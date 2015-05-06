#ifdef __APPLE__
#  define error printf
#endif
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>


void myAPI_encrypt_file(int);
	
void myAPI_decrypt_file(int);
	
