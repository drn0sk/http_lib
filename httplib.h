#ifndef HTTP_LIBRARY
#define HTTP_LIBRARY

#include <stddef.h>
#include <stdbool.h>

struct HTTPVersion {
	long major, minor;
};

enum Method {
	UNSUPPORTED = 0,
	GET,
	HEAD,
	POST,
};
typedef enum Method Method;

const char *strmeth(Method m);

bool url_decode(char *src, char **dst, size_t len);
bool url_encode(char *src, char **dst, size_t len);

typedef struct headers *headers;
struct headers {
	char *header;
	char *value;
	headers rest;
};

void free_headers(headers hdrs);
bool add_header(headers *h, const char *header, char *value);
bool add_header_const(headers *h, const char *header, const char *value);
bool update_header(headers *h, const char *header, char *value);
bool update_header_const(headers *h, const char *header, const char *value);
bool append_header(headers *h, const char *header, char *value);
bool append_header_const(headers *h, const char *header, const char *value);
const char *get_header(headers h, const char *header);
bool contains_header(headers h, const char *header);

#endif /* HTTP_LIBRARY */
