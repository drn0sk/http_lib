#ifndef HTTPLIB_UTILS
#define HTTPLIB_UTILS

#include "httplib.h"
#include <sys/types.h>

void strtoupper(char *s);
char *trim(char *s);
// any function where grow(n) > n
size_t grow(size_t old_len);
// realloc but frees ptr on error
void *reallocfree(void *ptr, size_t size);

bool sendall(int sock, const void* msg, size_t len, int flags);
// returns -1 on error or if recv was interrupted, 0 on success, and 1 if connection was closed
int recvall(int sock, void *msg, size_t len, int flags);
// returns -1 on error or if recv was interrupted, 0 if sock was closed, >0 on success
ssize_t discard(int sockfd, size_t size);
// returns -1 on error or if recv was interrupted, 0 on success, and 1 if connection was closed
int recvline(int sock, char **msg, size_t *len);
// returns -2 if headers were invalid, -1 on other errors or if recv was interrupted, 0 if successful, 1 if connection was closed
int read_headers(int sfd, headers *h);

typedef struct chunk *chunks;
struct chunk {
	size_t size;
	char *data;
	chunks next;
};

void free_chunks(chunks c);
bool add_chunk(chunks *c, size_t size, char *data);
// returns -1 on error or if recv was interrupted, 0 on success, and 1 if connection was closed
int read_chunked(int sockfd, char **content, size_t *content_len, bool discard);

#endif /* HTTPLIB_UTILS */
