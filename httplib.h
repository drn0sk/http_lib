#ifndef HTTP_LIBRARY
#define HTTP_LIBRARY

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

bool url_decode(char *src, char **dst, size_t len);
bool url_encode(char *src, char **dst, size_t len);

typedef struct headers *headers;
struct headers {
	char *header;
	char *value;
	headers rest;
};

void free_headers(headers hdrs);
bool add_header(headers *hdrs, char *header, char *value);
bool update_header(headers *hdrs, char *header, char *value);
bool append_header(headers *hdrs, char *header, char *value);
const char *get_header(headers hdrs, char *header);
bool contains_header(headers hdrs, char *header);

#endif /* HTTP_LIBRARY */
