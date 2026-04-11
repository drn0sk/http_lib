#ifndef HTTP_SERVER
#define HTTP_SERVER

#include "httplib.h"
#include <time.h>

typedef struct query *query_list;
struct query {
	char *param, *value;
	query_list rest;
};

const char *get_query(query_list q, char *param);
bool contains_query(query_list q, char *param);

typedef struct cookie *cookies;
struct cookie {
	char *name, *value;
	cookies rest;
};

const char *get_cookie(cookies c, char *name);

struct HTTP_Request_Handlers {
// *out_fd is a file descriptor with length *content_len
// on input *h is the headers recieved from the client
// on output *h is the headers sent to the client
int (*get_req_handler)(char *target, query_list q, char *directory, headers *hdrs, cookies c, char **reason, char **content_type,int *out_fd, size_t *content_len, struct timespec *ctime, char **etag);
// post_req_handler is optional (can be set to NULL if POST requests are not supported)
// *out_fd is a file descriptor with length *content_len
// on input *h is the headers recieved from the client
// on output *h is the headers sent to the client
int (*post_req_handler)(char *target, query_list q, char *directory, char *request_body, size_t request_body_size, headers *hdrs, cookies c, char **reason, char **content_type,int *out_fd, size_t *content_len, struct timespec *ctime, char **etag);
};

// set by the server function
// true if the current process is a child process
// false if it is the parent process
// can be used to do cleanup only in the parent process after the server function exits
extern bool child;

// takes a char *directory to serve
// returns true on successful termination or false on error
bool server(char *directory, struct HTTP_Request_Handlers hls, char *log);

#endif /* HTTP_SERVER */
