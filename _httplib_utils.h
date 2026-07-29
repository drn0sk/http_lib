#ifndef HTTPLIB_UTILS
#define HTTPLIB_UTILS

#include "httplib.h"
#include <sys/types.h>
#include <openssl/ssl.h>

typedef enum {
	NORMAL,
	SSL_CONN
} CONNECTION_TYPE;

typedef struct {
	CONNECTION_TYPE type;
	union {
		int fd;
		struct {
			SSL *ssl;
			SSL_CTX *ctx;
		};
	};
} conn_sock;

void strtoupper(char *s);
char *trim(char *s);
// any function where grow(n) > n
size_t grow(size_t old_len);
// realloc but frees ptr on error
void *reallocfree(void *ptr, size_t size);

int socket_close(conn_sock sock);
bool sendall(conn_sock sock, const void* msg, size_t len, int flags, int logfile);
// returns -1 on error or if recv was interrupted, 0 on success, and 1 if connection was closed
int recvall(conn_sock sock, void *msg, size_t len, int flags, int logfile);
// returns -1 on error or if recv was interrupted, 0 if sock was closed, >0 on success
ssize_t discard(int fd, size_t size, int logfile);
ssize_t sock_discard(conn_sock sock, size_t size, int logfile);
// returns -1 on error or if recv was interrupted, 0 on success, and 1 if connection was closed
int recvline(conn_sock sock, char **msg, size_t *len, int logfile);
// returns -2 if headers were invalid, -1 on other errors or if recv was interrupted, 0 if successful, 1 if connection was closed
int read_headers(conn_sock s, headers *h, int logfile);

typedef struct chunk *chunks;
struct chunk {
	size_t size;
	char *data;
	chunks next;
};

void free_chunks(chunks c);
bool add_chunk(chunks *c, size_t size, char *data);
// returns -1 on error or if recv was interrupted, 0 on success, and 1 if connection was closed
int read_chunked(conn_sock sock, char **content, size_t *content_len, bool discard, int logfile);

#endif /* HTTPLIB_UTILS */
