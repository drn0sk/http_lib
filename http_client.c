#include "http_client.h"
#include "_httplib_utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <fcntl.h>

typedef struct url_list_node *url_list;
struct url_list_node {
	char *url;
	url_list tail;
};

static void free_url_list(url_list l) {
	url_list tmp;
	while(l) {
		free(l->url);
		tmp = l;
		l = l->tail;
		free(tmp);
	}
}

static bool add_url(url_list *l, char *url) {
	url_list new_list = (url_list)malloc(sizeof(struct url_list_node));
	if(!new_list) return false;
	new_list->url = url;
	new_list->tail = *l;
	*l = new_list;
	return true;
}

static bool contains_url(url_list l, char *url) {
	for(;l;l=l->tail) {
		if(!strcmp(l->url, url)) return true;
	}
	return false;
}

void free_status(status *st) {
	free(st->reason);
	st->reason = NULL;
}

//static void *get_in_addr(struct sockaddr *sa, int logfile) {
//        switch(sa->sa_family) {
//        case AF_INET:
//                // IPv4
//                return &(((struct sockaddr_in*)sa)->sin_addr);
//                break;
//        case AF_INET6:
//                // IPv6
//                return &(((struct sockaddr_in6*)sa)->sin6_addr);
//                break;
//        default:
//                // ???
//                if(logfile >= 0) dprintf(logfile, "Unknown family:\t%d\n", sa->sa_family);
//                return NULL;
//                break;
//        }
//}

static bool parse_status(char *status_line, status *st, int logfile) {
	char *sv = NULL;
	char *ver, *codestr, *reason, *v1, *v2;
	ver = strtok_r(status_line, " ", &sv);
	if(!ver) return false;
	codestr = strtok_r(NULL, " ", &sv);
	if(!codestr) return false;
	reason = strtok_r(NULL, "\r\n", &sv);
	char *rest;
	if((rest = strtok_r(NULL, "\n", &sv)) && *rest) {
                if(logfile >= 0) dprintf(logfile, "Error: unable to parse status line.\n\tversion: '%s'\n\tstatus code: '%s'\n\treason phrase: '%s'\n\t extra: '%s'\n", ver, codestr, reason, rest);
                return false;
        }
	char *sv2 = NULL;
	if(strncmp(strtok_r(ver, "/", &sv2), "HTTP", 4)) return false;
	ver = strtok_r(NULL, "", &sv2);
	char *sv3 = NULL;
	v1 = strtok_r(ver, ".", &sv3);
	v2 = strtok_r(NULL, "", &sv3);
	long major, minor;
	int code;
	code = (int)strtol(codestr, NULL, 10);
	major = strtol(v1, NULL, 10);
	minor = strtol(v2, NULL, 10);
	st->code = code;
	st->version.major = major;
	st->version.minor = minor;
	st->reason = strdup((reason) ? reason : "");
	if(!st->reason) return false;
	return true;
}

// perfoms a get request to protocol://hostname for location using headers in h on input if not NULL
// returns status in stat, headers in h, and contents in contents (length in contents_len)
// return value of true for success, and false otherwise
static bool _get_request(char *hostname, char *location, char *protocol, char *query, char *frag, status *stat, headers *h, void **contents, uintmax_t *contents_len, int logfile) {
	struct addrinfo hints = {0}, *servinfo;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	int rv;
	char decoded_name[strlen(hostname) + 1];
	char *dnamep = decoded_name;
	if(!url_decode(hostname, &dnamep, strlen(hostname) + 1)) return false;
	if((rv = getaddrinfo(decoded_name, protocol, &hints, &servinfo)) != 0) {
		if(logfile >= 0) dprintf(logfile, "Error: %s\n", gai_strerror(rv));
		free_headers(*h);
		return false;
	}

	struct addrinfo *p;
	int sockfd = -1;
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}
		if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			continue;
		}
		break;
	}

	if(p == NULL) {
		if(logfile >= 0) dprintf(logfile, "Error: could not find hostname: '%s', with protocol: '%s'\n", decoded_name, protocol);
		free_headers(*h);
		if(sockfd >= 0) close(sockfd);
		freeaddrinfo(servinfo);
		return false;
	}
	bool https = (((struct sockaddr_in*)p->ai_addr)->sin_port == 443);
	freeaddrinfo(servinfo);
	conn_sock conn = {0};
	if(https) {
		conn.type = SSL_CONN;
		conn.ctx = SSL_CTX_new(TLS_client_method());
		if(!conn.ctx) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to create ssl_ctx\n");
			free_headers(*h);
			close(sockfd);
			if(logfile >= 0) print_ssl_errors(logfile);
			return false;
		}
		SSL_CTX_set_verify(conn.ctx, SSL_VERIFY_PEER, NULL);
		if(!SSL_CTX_set_default_verify_paths(conn.ctx)) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to set certificate store path\n");
			free_headers(*h);
			close(sockfd);
			if(logfile >= 0) print_ssl_errors(logfile);
			return false;
		}
		if(!SSL_CTX_set_min_proto_version(conn.ctx, TLS1_2_VERSION)) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to set minimum TLS version\n");
			free_headers(*h);
			close(sockfd);
			if(logfile >= 0) print_ssl_errors(logfile);
			return false;
		}
		conn.ssl = SSL_new(conn.ctx);
		if(!conn.ssl) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to create ssl\n");
			free_headers(*h);
			close(sockfd);
			SSL_CTX_free(conn.ctx);
			if(logfile >= 0) print_ssl_errors(logfile);
			return false;
		}
		if(!SSL_set_fd(conn.ssl, sockfd)) {
			if(logfile >= 0) dprintf(logfile, "Error: \n");
			free_headers(*h);
			close(sockfd);
			socket_close(conn, logfile);
			SSL_CTX_free(conn.ctx);
			if(logfile >= 0) print_ssl_errors(logfile);
			return false;
		}
		if(!SSL_set_tlsext_host_name(conn.ssl, hostname)) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to set hostname\n");
			free_headers(*h);
			socket_close(conn, logfile);
			SSL_CTX_free(conn.ctx);
			if(logfile >= 0) print_ssl_errors(logfile);
			return false;
		}
		if(!SSL_set1_host(conn.ssl, hostname)) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to set hostname\n");
			free_headers(*h);
			socket_close(conn, logfile);
			SSL_CTX_free(conn.ctx);
			if(logfile >= 0) print_ssl_errors(logfile);
			return false;
		}
		if(SSL_connect(conn.ssl) <= 0) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to connect\n");
			if(SSL_get_verify_result(conn.ssl) != X509_V_OK &&
					logfile >= 0) dprintf(logfile, "Verify error: %s\n",
						X509_verify_cert_error_string(SSL_get_verify_result(conn.ssl)));
			free_headers(*h);
			socket_close(conn, logfile);
			SSL_CTX_free(conn.ctx);
			if(logfile >= 0) print_ssl_errors(logfile);
			return false;
		}
	} else {
		conn.type = NORMAL;
		conn.fd = sockfd;
	}
	size_t hdrs_len = 1; // length of terminating NULL byte "\0"
	for(headers tmp = *h; tmp; tmp = tmp->rest) {
		if(!*tmp->header || !*tmp->value) {
			free_headers(*h);
			socket_close(conn, logfile);
			SSL_CTX_free(conn.ctx);
			if(logfile >= 0) print_ssl_errors(logfile);
			return false;
		}
		hdrs_len += strlen(tmp->header) + strlen(tmp->value) + 4; // length of header + length of value + (length of "\r\n" and ": ")
	}
	char *hdrs = malloc(hdrs_len);
	if(!hdrs) {
		free_headers(*h);
		socket_close(conn, logfile);
		SSL_CTX_free(conn.ctx);
		if(logfile >= 0) print_ssl_errors(logfile);
		return false;
	}
	char *hdrs_end = hdrs;
	for(headers tmp = *h; tmp; tmp = tmp->rest) {
		hdrs_end = mempcpy(hdrs_end, tmp->header, strlen(tmp->header));
		*hdrs_end++ = ':';
		*hdrs_end++ = ' ';
		hdrs_end = mempcpy(hdrs_end, tmp->value, strlen(tmp->value));
		*hdrs_end++ = '\r';
		*hdrs_end++ = '\n';
	}
	*hdrs_end = '\0';
	free_headers(*h);
	*h = NULL;
	char *request;
	if(asprintf(&request, "GET %s%s%s%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n%s\r\n", location, (query)?"?":"", (query)?query:"", (frag)?"#":"", (frag)?frag:"", hostname, hdrs) == -1) {
		if(logfile >= 0) dprintf(logfile, "Error: failed to create request string.\n");
		socket_close(conn, logfile);
		SSL_CTX_free(conn.ctx);
		if(logfile >= 0) print_ssl_errors(logfile);
		free(hdrs);
		return false;
	}
	free(hdrs);
	size_t len = strlen(request);
	if(!sendall(conn, request, len, 0, logfile)) {
		if(logfile >= 0) dprintf(logfile, "Error: failed to send request.\n");
		socket_close(conn, logfile);
		SSL_CTX_free(conn.ctx);
		if(logfile >= 0) print_ssl_errors(logfile);
		free(request);
		return false;
	}
	free(request);

	// receive response

	char *statusLine = NULL;
	size_t stLen = 0;
	if(recvline(conn, &statusLine, &stLen, logfile)) {
		if(logfile >= 0) dprintf(logfile, "recvline: %s\n", strerror(errno));
		socket_close(conn, logfile);
		SSL_CTX_free(conn.ctx);
		if(logfile >= 0) print_ssl_errors(logfile);
		free(statusLine);
		return false;
	}

	if(!parse_status(statusLine, stat, logfile)) {
		if(logfile >= 0) dprintf(logfile, "Error: failed to parse status: %s\n", statusLine);
		socket_close(conn, logfile);
		SSL_CTX_free(conn.ctx);
		if(logfile >= 0) print_ssl_errors(logfile);
		free(statusLine);
		return false;
	}
	
	free(statusLine);

	// have status
	if(stat->code >= 400) {
		// error
		socket_close(conn, logfile);
		SSL_CTX_free(conn.ctx);
		if(logfile >= 0) print_ssl_errors(logfile);
		free_status(stat);
		return true;
	}

	if(read_headers(conn, h, logfile)) {
		if(logfile >= 0) dprintf(logfile, "Error: failed to read headers.\n");
		socket_close(conn, logfile);
		SSL_CTX_free(conn.ctx);
		if(logfile >= 0) print_ssl_errors(logfile);
		free_status(stat);
		return false;
	}

	if(contains_header(*h, "Transfer-Encoding") && strncmp(get_header(*h, "Transfer-Encoding"), "chunked", 7) == 0) {
		// chunked encoding
		if(read_chunked(conn, (char**)contents, contents_len, false, logfile)) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to read chunked encoding\n");
			socket_close(conn, logfile);
			SSL_CTX_free(conn.ctx);
			if(logfile >= 0) print_ssl_errors(logfile);
			free_status(stat);
			free_headers(*h);
			return false;
		}
	} else if(contains_header(*h, "Content-Length")) {
		*contents_len = strtol(get_header(*h, "Content-Length"), NULL, 10);
		*contents = malloc(*contents_len+1);
		if(!*contents) {
			socket_close(conn, logfile);
			SSL_CTX_free(conn.ctx);
			if(logfile >= 0) print_ssl_errors(logfile);
			free_status(stat);
			free_headers(*h);
			return false;
		}
		if(recvall(conn, *contents, *contents_len, 0, logfile)) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to read content with length: %ld\n", *contents_len);
			socket_close(conn, logfile);
			SSL_CTX_free(conn.ctx);
			if(logfile >= 0) print_ssl_errors(logfile);
			free_status(stat);
			free_headers(*h);
			free(*contents);
			return false;
		}
		((uint8_t*)*contents)[*contents_len] = '\0';
	}
	socket_close(conn, logfile);
	SSL_CTX_free(conn.ctx);
	if(logfile >= 0) print_ssl_errors(logfile);
	return true;
}

static char *last_protocol = NULL, *last_hostname = NULL, *last_location = NULL, *last_query;
// tries to parse url (if url is relative it is parsed relative to the last parsed url)
// sets hostname and location
// only sets protocol if one was specified in the url
// only sets query and fragment if they were specified
static bool parse_url(char *url, char **hostname, char **location, char **protocol, char **query, char **fragment, int logfile) {
	if(!url) return false;
	*hostname = NULL;
	*location = NULL;
	*protocol = NULL;
	*query = NULL;
	*fragment = NULL;
	char *sv = NULL, *t, *tmp;
	char *tmpurl_start = strdup(url);
	char *tmpurl = tmpurl_start;
	if(!tmpurl) return false;
	if((tmp = strstr(tmpurl, "://"))) {
		*tmp = '\0';
		t = tmpurl;
		if(tmp == tmpurl) {
			if(logfile >= 0) dprintf(logfile, "Invalid url (had '://' but no scheme): %s\n", url);
			free(tmpurl_start);
			return false;
		}
		tmpurl = tmp + 1;
		*protocol = strdup(t);
		if(!*protocol) {
			if(logfile >= 0) dprintf(logfile, "strdup: %s\n", strerror(errno));
			free(tmpurl_start);
			return false;
		}
	} else if(last_protocol && *last_protocol) {
		*protocol = last_protocol;
	}
	if(*tmpurl == '/' && *(tmpurl + 1) == '/') {
		t = strtok_r(tmpurl, "/", &sv);
		if(!t) {
			if(logfile >= 0) dprintf(logfile, "Invalid url (had '//' but no hostname): %s\n", url);
			free(tmpurl_start);
			if(*protocol != last_protocol) free(*protocol);
			*protocol = NULL;
			return false;
		}
		*hostname = strdup(t);
		if(!*hostname) {
			if(logfile >= 0) dprintf(logfile, "strdup: %s\n", strerror(errno));
			free(tmpurl_start);
			if(*protocol != last_protocol) free(*protocol);
			*protocol = NULL;
			return false;
		}
		tmpurl = strtok_r(NULL, "", &sv);
		if(tmpurl) {
			*--tmpurl = '/';
		} else {
			tmpurl = "/";
		}
		sv = NULL;
	} else {
		if(!(last_hostname && *last_hostname)) {
			if(logfile >= 0) dprintf(logfile, "Invalid url (relative path but no base hostname): %s\n", url);
			free(tmpurl_start);
			if(*protocol != last_protocol) free(*protocol);
			*protocol = NULL;
			return false;
		}
		*hostname = last_hostname;
	}
	bool has_query = strchrnul(tmpurl, '?') < strchrnul(tmpurl, '#');
	bool has_frag = strchr(tmpurl, '#');
	t = (*tmpurl == '?' || *tmpurl == '#') ? NULL : strtok_r(tmpurl, "?#", &sv);
	if(t) {
		if(*t == '/') {
			*location = strdup(t);
			if(!*location) {
				if(logfile >= 0) dprintf(logfile, "strdup: %s\n", strerror(errno));
				if(*protocol != last_protocol) free(*protocol);
				*protocol = NULL;
				if(*hostname != last_hostname) free(*hostname);
				*hostname = NULL;
				free(tmpurl_start);
				return false;
			}
			if(strlen(*location) > 1 && (*location)[strlen(*location) - 1] == '/') (*location)[strlen(*location) - 1] = '\0';
		} else {
			char *tmp_location = (char*)malloc(strlen(t)+2);
			if(!tmp_location) {
				if(logfile >= 0) dprintf(logfile, "malloc: %s\n", strerror(errno));
				if(*protocol != last_protocol) free(*protocol);
				*protocol = NULL;
				if(*hostname != last_hostname) free(*hostname);
				*hostname = NULL;
				free(tmpurl_start);
				return false;
			}
			*tmp_location = '/';
			strcpy(tmp_location+1, t);
			if(strlen(tmp_location) > 1 && tmp_location[strlen(tmp_location) - 1] == '/') tmp_location[strlen(tmp_location) - 1] = '\0';
			if(last_location && *last_location && ((strlen(last_location) == 1) ? *last_location != '/' : true)) {
				if(*last_location != '/') {
					if(logfile >= 0) dprintf(logfile, "Error: invalid last location: %s\n", last_location);
					if(*protocol != last_protocol) free(*protocol);
					*protocol = NULL;
					if(*hostname != last_hostname) free(*hostname);
					*hostname = NULL;
					free(tmp_location);
					free(tmpurl_start);
					return false;
				}
				*strrchr(last_location, '/') = '\0';
				*location = malloc(strlen(last_location) + strlen(tmp_location) + 1);
				if(!*location) {
					if(logfile >= 0) dprintf(logfile, "malloc: %s\n", strerror(errno));
					if(*protocol != last_protocol) free(*protocol);
					*protocol = NULL;
					if(*hostname != last_hostname) free(*hostname);
					*hostname = NULL;
					free(tmp_location);
					free(tmpurl_start);
					return false;
				}
				strcpy(*location, last_location);
				strcat(*location, tmp_location);
				free(tmp_location);
			} else {
				*location = tmp_location;
			}
		}
	} else {
		if(!has_query && *protocol == last_protocol && *hostname == last_hostname) {
			*query = last_query;
		}
		if(last_location && *last_location == '/') {
			*location = last_location;
		}
	}
	if(has_query) {
		t = strtok_r(NULL, "#", &sv);
		*query = strdup(t);
		if(!*query) {
			if(logfile >= 0) dprintf(logfile, "strdup: %s\n", strerror(errno));
			free(tmpurl_start);
			if(*protocol != last_protocol) free(*protocol);
			*protocol = NULL;
			if(*hostname != last_hostname) free(*hostname);
			*hostname = NULL;
			if(*location != last_location) free(*location);
			*location = NULL;
			return false;
		}
	}
	if(has_frag) {
		t = strtok_r(NULL, "", &sv);
		*fragment = strdup(t);
		if(!*fragment) {
			if(logfile >= 0) dprintf(logfile, "strdup: %s\n", strerror(errno));
			free(tmpurl_start);
			if(*protocol != last_protocol) free(*protocol);
			*protocol = NULL;
			if(*hostname != last_hostname) free(*hostname);
			*hostname = NULL;
			if(*location != last_location) free(*location);
			*location = NULL;
			if(*query != last_query) free(*query);
			*query = NULL;
			return false;
		}
	}
	free(tmpurl_start);
	int err = 0;
	char *tmp_last_protocol = (*protocol) ? strdup(*protocol) : NULL;
	if(*protocol && !tmp_last_protocol) err = errno;
	char *tmp_last_hostname = strdup(*hostname);
	if(!tmp_last_hostname) err = errno;
	char *tmp_last_location = (*location) ? strdup(*location) : NULL;
	if(*location && !tmp_last_location) err = errno;
	char *tmp_last_query = (*query) ? strdup(*query) : NULL;
	if(*query && !tmp_last_query) err = errno;
	if((*protocol && !tmp_last_protocol) || !tmp_last_hostname || (*location && !tmp_last_location) || (*query && !tmp_last_query)) {
		errno = err;
		if(logfile >= 0) dprintf(logfile, "strdup: %s\n", strerror(errno));
		if(*protocol != last_protocol) free(*protocol);
		*protocol = NULL;
		if(*hostname != last_hostname) free(*hostname);
		*hostname = NULL;
		if(*location != last_location) free(*location);
		*location = NULL;
		if(*query != last_query) free(*query);
		*query = NULL;
		if(has_frag) free(*fragment);
		*fragment = NULL;
		return false;
	}
	if(*protocol != last_protocol) free(last_protocol);
	if(*hostname != last_hostname) free(last_hostname);
	if(*location != last_location) free(last_location);
	if(*query != last_query) free(last_query);
	last_protocol = tmp_last_protocol;
	last_hostname = tmp_last_hostname;
	last_location = tmp_last_location;
	last_query = tmp_last_query;
	if(!*location) *location = strdup("/");
	if(!*protocol) *protocol = strdup("http");
	if(!*location || !*protocol) {
		if(*protocol != last_protocol) free(*protocol);
		*protocol = NULL;
		if(*hostname != last_hostname) free(*hostname);
		*hostname = NULL;
		if(*location != last_location) free(*location);
		*location = NULL;
		if(*query != last_query) free(*query);
		*query = NULL;
		if(has_frag) free(*fragment);
		*fragment = NULL;
		return false;
	}
	return true;
}

// perfoms a get request to url using headers in h on input if not NULL
// returns status in stat, headers in h, and contents in contents (length in contents_len)
// return value of true for success, and false otherwise
bool get_request(char *url, status *stat, headers *h, void **content, size_t *content_len, bool redir, char *log) {
	int logfile = -1;
	if(log) {
		// open log file
		logfile = open(log, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(logfile < 0) return false;
	}
	char *protocol, *hostname, *location, *query, *fragment;
	if(!parse_url(url, &hostname, &location, &protocol, &query, &fragment, logfile) || !hostname) {
		if(logfile >= 0) close(logfile);
		free(last_protocol);
		free(last_hostname);
		free(last_location);
		free(last_query);
		return false;
	}
	if(!isdigit(*protocol) && strcmp(protocol, "http")) {
		if(logfile >= 0) dprintf(logfile, "Error: unsupported protocol: '%s'\n", protocol);
		if(logfile >= 0) close(logfile);
		if(hostname) free(hostname);
		if(location) free(location);
		if(protocol) free(protocol);
		if(query) free(query);
		if(fragment) free(fragment);
		free(last_protocol);
		free(last_hostname);
		free(last_location);
		free(last_query);
		return false;
	}
	bool retv = _get_request(hostname, location, protocol, query, fragment, stat, h, content, content_len, logfile);
	if(!retv) {
		if(logfile >= 0) close(logfile);
		if(hostname) free(hostname);
		if(location) free(location);
		if(protocol) free(protocol);
		if(query) free(query);
		if(fragment) free(fragment);
		free(last_protocol);
		free(last_hostname);
		free(last_location);
		free(last_query);
		return retv;
	}
	if(hostname) free(hostname);
	if(location) free(location);
	if(protocol) free(protocol);
	if(query) free(query);
	if(fragment) free(fragment);
	url_list l = NULL;
	url = strdup(url);
	if(!url) {
		if(logfile >= 0) dprintf(logfile, "strdup: %s\n", strerror(errno));
		if(logfile >= 0) close(logfile);
		free(last_protocol);
		free(last_hostname);
		free(last_location);
		free(last_query);
		free_status(stat);
		free_headers(*h);
		free(*content);
		return false;
	}
	if(!add_url(&l, url)) {
		if(logfile >= 0) dprintf(logfile, "Error: failed to add url to list\n");
		if(logfile >= 0) close(logfile);
		free(last_protocol);
		free(last_hostname);
		free(last_location);
		free(last_query);
		free(url);
		free_status(stat);
		free_headers(*h);
		free(*content);
		return false;
	}
	while(redir && stat->code >= 300 && stat->code < 400) {
		const char *tmp = get_header(*h, "Location");
		if(!tmp) break;
		url = strdup(tmp);
		if(!url) {
			if(logfile >= 0) dprintf(logfile, "strdup: %s\n", strerror(errno));
			retv = false;
			break;
		}
		if(contains_url(l, url)) {
			if(logfile >= 0) dprintf(logfile, "Error: redirection loop to %s\n", url);
			free(url);
			retv = false;
			break;
		}
		status new_stat = {0};
		headers new_h = NULL;
		void *new_content = NULL;
		uintmax_t new_content_len = 0;
		if(!parse_url(url, &hostname, &location, &protocol, &query, &fragment, logfile) || !hostname) {
			free(url);
			retv = false;
			break;
		}
		if(!isdigit(*protocol) && strcmp(protocol, "http")) {
			if(logfile >= 0) dprintf(logfile, "Error: unsupported protocol: '%s'\n", protocol);
			if(hostname) free(hostname);
			if(location) free(location);
			if(protocol) free(protocol);
			if(query) free(query);
			if(fragment) free(fragment);
			free(url);
			retv = false;
			break;
		}
		if(!_get_request(hostname, location, protocol, query, fragment, &new_stat, &new_h, &new_content, &new_content_len, logfile)) {
			if(hostname) free(hostname);
			if(location) free(location);
			if(protocol) free(protocol);
			if(query) free(query);
			if(fragment) free(fragment);
			if(logfile >= 0) dprintf(logfile, "Error: failed to redirect to new location: %s\n", url);
			free(url);
			retv = false;
			break;
		}
		if(hostname) free(hostname);
		if(location) free(location);
		if(protocol) free(protocol);
		if(query) free(query);
		if(fragment) free(fragment);
		free_status(stat);
		free_headers(*h);
		free(*content);
		*stat = new_stat;
		*h = new_h;
		*content = new_content;
		*content_len = new_content_len;
		if(new_stat.code >= 400) break;
		if(!add_url(&l, url)) {
			if(logfile >= 0) dprintf(logfile, "Error: failed to add url to list\n");
			free(url);
			retv = false;
			break;
		}
	}
	free(last_protocol);
	free(last_hostname);
	free(last_location);
	free(last_query);
	free_url_list(l);
	if(logfile >= 0) close(logfile);
	if(!retv) {
		free_status(stat);
		free_headers(*h);
		free(*content);
	}
	return retv;
}
