#include "_httplib_utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <unistd.h>

bool url_decode(char *src, char **dst, size_t len) {
	if(!src) return false;
	if(!*dst) {
		len = strlen(src) + 1;
		*dst = malloc(len);
		if(!*dst) return false;
	}
	char *tmp = *dst;
	while(*src) {
		if(!len) return false;
		switch(*src) {
		case '%':
			src++;
			char hex[3];
			hex[0] = *src++;
			hex[1] = *src++;
			hex[2] = '\0';
			long lnum = strtol(hex, NULL, 16);
			char c = (char)(lnum & 0xFF);
			*tmp++ = c;
			break;
		default:
			*tmp++ = *src++;
		}
		len--;
	}
	*tmp = '\0';
	return true;
}
static const char hex_digits[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
bool url_encode(char *src, char **dst, size_t len) {
	if(!src) return false;
	if(!*dst) {
		len = 3*strlen(src) + 1;
		*dst = malloc(len);
		if(!*dst) return false;
	}
	char *tmp = *dst;
	while(*src) {
		if(!len) return false;
		if(isalnum(*src) || strchr("-._~", *src)) {
			*tmp++ = *src++;
			len--;
		} else {
			if(len < 3) return false;
			*tmp++ = '%';
			*tmp++ = hex_digits[((unsigned char)*src >> 4) & 0x0F];
			*tmp++ = hex_digits[(unsigned char)*src & 0x0F];
			src++;
			len -= 3;
		}
	}
	*tmp = '\0';
	return true;
}

static ssize_t recv_retry_err(conn_sock sock, void *msg, size_t len, int flags, int logfile) {
	ssize_t retval;
	size_t bytes = 0;
	while(true) {
		switch(sock.type) {
		case NORMAL:
			retval = recv(sock.fd, msg, len, flags);
			if(retval >= 0) bytes = retval;
			if(retval < 0) {
				switch(errno) {
					case ENOMEM:
						if(logfile >= 0) dprintf(logfile, "LOG: trying again\n");
						continue;
				}
				return -1;
			}
			break;
		case SSL_CONN:
			int (*fn)(SSL*,void*,size_t,size_t*) = (flags & MSG_PEEK) ? SSL_peek_ex : SSL_read_ex;
			retval = fn(sock.ssl, msg, len, &bytes);
			if(retval <= 0) {
				switch(SSL_get_error(sock.ssl, retval)) {
				case SSL_ERROR_ZERO_RETURN:
					return 0;
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_CONNECT:
				case SSL_ERROR_WANT_ACCEPT:
					if(logfile >= 0) dprintf(logfile, "LOG: trying again\n");
					continue;
				}
				return -1;
			}
			break;
		}
		return bytes;
	}
}

// returns -1 on error or if recv was interrupted, 0 if sock was closed, >0 on success
// sets *len to the total number of bytes read
// if logfile >= 0: prints logging information to logfile
static ssize_t recv_retry(conn_sock sock, void *msg, size_t *len, int flags, int logfile) {
	size_t read = 0;
	ssize_t retval;
	while(read < *len) {
		if(read > 0 && logfile >= 0) dprintf(logfile, "LOG: read only %zu of %zu bytes so far, reading the rest\n", read, *len);
		retval = recv_retry_err(sock, (uint8_t*)msg + read, *len - read, flags, logfile);
		if(retval <= 0) {
			*len = read;
			return retval;
		}
		read += retval;
	}
	*len = read;
	return read;
}

// returns -1 on error or if recv was interrupted, 0 on success, and 1 if connection was closed
int recvall(conn_sock sock, void *msg, size_t len, int flags, int logfile) {
	ssize_t retval = recv_retry(sock, msg, &len, flags | MSG_WAITALL, logfile);
	return (retval < 0) ? retval : !retval;
}

// returns -1 on error or if recv was interrupted, 0 if sock was closed, >0 on success
ssize_t discard(int fd, size_t size, int logfile) {
	return sock_discard((conn_sock){.type = NORMAL, .fd = fd}, size, logfile);
}
ssize_t sock_discard(conn_sock sock, size_t size, int logfile) {
	char *b;
	switch(sock.type) {
	case NORMAL:
		b = NULL;
		break;
	case SSL_CONN:
		{
			char buf[size];
			b = buf;
		}
	}
	return recv_retry(sock, b, &size, MSG_TRUNC | MSG_WAITALL, logfile);
}

// any function where grow(n) > n
size_t grow(size_t old_len) {
	return (old_len) ? old_len + (old_len >> 2) : 4; // old_len * 1.5 if old_len > 0, otherwise 4
}

// realloc but frees ptr on error
void *reallocfree(void *ptr, size_t size) {
	void *tmp = realloc(ptr, size);
	if(!tmp) free(ptr);
	return tmp;
}

#define BUFSIZE 100
// returns -1 on error or if recv was interrupted, 0 on success, and 1 if connection was closed
int recvline(conn_sock sock, char **msg, size_t *len, int logfile) {
	if(!*msg) *len = 0;
	static char buf[BUFSIZE] = {0};
	ssize_t buf_len = BUFSIZE;
	size_t line_len = 0;
	char *nl;
	int retval;
	do {
		if(line_len > 0) {
			if(*len < line_len) {
				while(*len < line_len) *len = grow(*len);
				*msg = reallocfree(*msg, *len); // allocate space for the line and the terminating null byte
				if(!*msg) return -1;
			}
			retval = recvall(sock, *msg + line_len - buf_len, buf_len, 0, logfile);
			if(retval) return retval;
		}
		buf_len = recv_retry_err(sock, buf, BUFSIZE, MSG_PEEK, logfile);
		if(buf_len < 0) return -1;
		if(buf_len == 0) return 1;
		line_len += buf_len;
		nl = memchr(buf, '\n', buf_len);
	} while(!nl);
	line_len -= buf_len;
	buf_len = (size_t)(nl - buf) + 1; // length of rest of line + space for the '\n' itself
	line_len += buf_len;
	if(*len <= line_len) {
		while(*len <= line_len) *len = grow(*len);
		*msg = reallocfree(*msg, *len); // allocate space for the line and the terminating null byte
		if(!*msg) return -1;
	}
	(*msg)[line_len] = '\0';
	return recvall(sock, *msg + line_len - buf_len, buf_len, 0, logfile);
}

bool sendall(conn_sock sock, const void *msg, size_t len, int flags, int logfile) {
	size_t sent = 0;
	ssize_t retval;
	while(sent < len) {
		if(sent > 0 && logfile >= 0) dprintf(logfile, "LOG: sent only %zu of %zu bytes so far, sending the rest\n", sent, len);
		switch(sock.type) {
		case NORMAL:
			retval = send(sock.fd, (uint8_t*)msg + sent, len - sent, flags);
			if(retval < 0) {
				switch(errno) {
				case EINTR:
				case ENOBUFS:
				case ENOMEM:
				case ECONNRESET:
					if(logfile >= 0) dprintf(logfile, "LOG: trying again\n");
					continue;
				}
				return false;
			}
			sent += retval;
			break;
		case SSL_CONN:
			size_t bytes;
			retval = SSL_write_ex(sock.ssl, (uint8_t*)msg + sent, len - sent, &bytes);
			if(!retval) {
				switch(SSL_get_error(sock.ssl, retval)) {
                                case SSL_ERROR_WANT_READ:
                                case SSL_ERROR_WANT_WRITE:
                                case SSL_ERROR_WANT_CONNECT:
                                case SSL_ERROR_WANT_ACCEPT:
                                        if(logfile >= 0) dprintf(logfile, "LOG: trying again\n");
                                        continue;
				}
                                return false;
			}
			sent += bytes;
		}
	}
	return true;
}

void free_headers(headers h) {
	headers tmp;
	while(h) {
		free(h->header);
		free(h->value);
		tmp = h;
		h = h->rest;
		free(tmp);
	}
}

bool add_header(headers *h, char *header, char *value) {
	if(!header || !value) return false;
	headers head = (headers)malloc(sizeof(struct headers));
	if(!head) return false;
	head->header = header;
	head->value = value;
	head->rest = *h;
	*h = head;
	return true;
}

bool update_header(headers *h, char *header, char *value) {
	if(!header || !value) return false;
	for(headers h2 = *h; h2; h2 = h2->rest) {
		if(strcasecmp(header, h2->header) == 0) {
			free(h2->value);
			h2->value = value;
			return true;
		}
	}
	return add_header(h, header, value);
}

bool append_header(headers *h, char *header, char *value) {
	if(!header || !value) return false;
	for(headers h2 = *h; h2; h2 = h2->rest) {
		if(strcasecmp(header, h2->header) == 0) {
			char *tmp = realloc(h2->value, strlen(h2->value) + strlen(value) + 2);
			if(!tmp) return false;
			h2->value = tmp;
			strcat(h2->value, ",");
			strcat(h2->value, value);
			return true;
		}
	}
	return add_header(h, header, value);
}

const char *get_header(headers h, char *header) {
	if(!header) {
		return NULL;
	}
	for(;h;h=h->rest) {
		if(strcasecmp(header, h->header) == 0) {
			return h->value;
		}
	}
	return NULL;
}

bool contains_header(headers h, char *header) {
	return (bool)get_header(h, header);
}

void strtoupper(char *s) {
	for(;*s;s++) {
		*s = toupper(*s);
	}
}

char *trim(char *s) {
	if(*s == '\0') {
		return s;
	}
	while(*s == ' ' || *s == '\t') {
		s++;
	}
	char *e = s + strlen(s);
	do {
		e--;
	} while(*e == ' ' || *e == '\t');
	*(e+1) = '\0';
	return s;
}

// returns -2 if headers were invalid, -1 on other errors or if recv was interrupted, 0 if successful, 1 if connection was closed
int read_headers(conn_sock s, headers *h, int logfile) {
	char *line = NULL, *i;
	size_t len;
	headers hdrs = NULL;
	char *svp = NULL;
	int retval;
	char *header, *value;
	while(true) {
		if((retval = recvline(s, &line, &len, logfile))) {
			free_headers(hdrs);
			break;
		}
		retval = -1;
		i = strrchr(line, '\r');
		if(!i) {
			i = strrchr(line, '\n');
			if(i == NULL) {
				free_headers(hdrs);
				retval = -2;
				break;
			}
		}
		*i = '\0';
		if(strlen(line) == 0) {
			retval = 0;
			break;
		}
		header = strtok_r(line, ":", &svp);
		if(!header) {
			free_headers(hdrs);
			retval = -2;
			break;
		}
		if(header[0] == ' ' || header[0] == '\t' || header[0] == '\0' || header[strlen(header)-1] == ' ' || header[strlen(header)-1] == '\t') {
			free_headers(hdrs);
			retval = -2;
			break;
		}
		header = strdup(header);
		if(!header) {
			free_headers(hdrs);
			break;
		}
		strtoupper(header);
		value = strtok_r(NULL, "", &svp);
		if(!value) {
			free(header);
			retval = -2;
			continue;
		}
		value = trim(value);
		value = strdup(value);
		if(!value) {
			free(header);
			free_headers(hdrs);
			break;
		}
		if(!append_header(&hdrs, header, value)) {
			free(header);
			free(value);
			free_headers(hdrs);
			break;
		}
	}
	if(line) free(line);
	if(!retval) *h = hdrs;
	return retval;
}

void free_chunks(chunks c) {
	chunks tmp;
	while(c) {
		free(c->data);
		tmp = c;
		c = c->next;
		free(tmp);
	}
}

bool add_chunk(chunks *c, size_t size, char *data) {
	chunks c_new = (chunks)malloc(sizeof(struct chunk));
	if(!c_new) return false;
	c_new->size = size;
	c_new->data = data;
	c_new->next = *c;
	*c = c_new;
	return true;
}

// returns -1 on error or if recv was interrupted, 0 on success, and 1 if connection was closed
int read_chunked(conn_sock sock, char **content, size_t *content_len, bool discard, int logfile) {
	int retval;
	char crlf[2];
	chunks ch = NULL;
	char *line = NULL;
	size_t len = 0;
	char *buff = NULL;
	while(true) {
		if((retval = recvline(sock, &line, &len, logfile))) {
			free_chunks(ch);
			free(line);
			return retval;
		}
		size_t size;
		if(sscanf(line, "%zx", &size) < 1) {
			free_chunks(ch);
			free(line);
			return -1;
		}
		if(size == 0) break;
		buff = (char*)malloc(size);
		if(!buff) {
			free_chunks(ch);
			free(line);
			return -1;
		}
		if((retval = recvall(sock, buff, size, 0, logfile))) {
			free_chunks(ch);
			free(line);
			free(buff);
			return retval;
		}
		if(!add_chunk(&ch, size, buff)) {
			free_chunks(ch);
			free(line);
			free(buff);
			return -1;
		}
		if((retval = recvall(sock, &crlf, 2, 0, logfile)) || strncmp((char*)&crlf, "\r\n", 2)) {
			free_chunks(ch);
			free(line);
			return (retval) ? retval : -1;
		}
	}
	do {
		if((retval = recvline(sock, &line, &len, logfile))) {
			free_chunks(ch);
			free(line);
			return retval;
		}
	} while(*line != '\r');
	free(line);
	if(!discard) {
		*content_len = 0;
		for(chunks c = ch; c; c = c->next) {
			*content_len += c->size;
		}
		*content = (char*)malloc(*content_len + 1);
		if(!*content) {
			free_chunks(ch);
			return -1;
		}
		size_t i = *content_len;
		((char*)*content)[i] = '\0';
		for(chunks c = ch; c; c = c->next) {
			i -= c->size;
			memcpy(*content + i, c->data, c->size);
		}
		if(i != 0) {
			free_chunks(ch);
			free(*content);
			return -1;
		}
	}
	free_chunks(ch);
	return 0;
}

int socket_close(conn_sock sock) {
	int retval = 1;
	if(sock.type == SSL_CONN) {
		while( (retval = SSL_shutdown(sock.ssl)) == 0 ) {}
		int sfd = SSL_get_fd(sock.ssl);
		SSL_free(sock.ssl);
		SSL_CTX_free(sock.ctx);
		if(sfd >= 0) close(sfd);
	}
	return (retval > 0) && close(sock.fd);
}
