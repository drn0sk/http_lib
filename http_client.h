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

// performs a get request to url, using headers in h on input if it's not NULL
// returns status in stat, headers in h, and contents in content (length of content in content_len)
// when done using them: stat.reason needs to be freed, headers have to be freed using free_headers, and content has to be freed
// returns true on success, false on error;
bool get_request(char *url, status *stat, headers *h, void **content, size_t *content_len, bool automatic_redirection);

#endif /* HTTP_CLIENT */
