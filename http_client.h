#ifndef HTTP_CLIENT
#define HTTP_CLIENT

#include "httplib.h"

struct status {
	struct HTTPVersion version;
	int code;
	char *reason;
};
typedef struct status status;

void free_status(status *st);

// perfoms a HTTP(S) request with method m to url using headers in h on input if not NULL and body if not NULL and body_len > 0
// if content_type is not NULL, the Content-Type header is set to it
// if log is not NULL error messages and other information is output to it, otherwise nothing is output
// returns status in stat, headers in h, and contents in content (length of content in content_len)
// when done using them: stat.reason needs to be freed, headers have to be freed using free_headers, and content has to be freed
// returns true on success, false on error;
bool http_request(Method m, char *url, status *stat, headers *h, char *body, uintmax_t body_len, char *content_type, void **content, size_t *content_len, bool redir, char *log);

bool get_request(char *url, status *stat, headers *h, char *body, uintmax_t body_len, char *content_type, void **content, size_t *content_len, bool redir, char *log);
bool head_request(char *url, status *stat, headers *h, char *body, uintmax_t body_len, char *content_type, void **content, size_t *content_len, bool redir, char *log);
bool post_request(char *url, status *stat, headers *h, char *body, uintmax_t body_len, char *content_type, void **content, size_t *content_len, bool redir, char *log);

#endif /* HTTP_CLIENT */
