#define _GNU_SOURCE
#include "http_server.h"
#include "_httplib_utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/sendfile.h>
#include <time.h>
#include <fcntl.h>

static void free_query(query_list q) {
	query_list tmp;
	while(q) {
		free(q->param);
		free(q->value);
		tmp = q;
		q = q->rest;
		free(tmp);
	}
}

static bool add_query(query_list *q, char *param, char *value) {
	query_list q_new = malloc(sizeof(struct query));
	if(!q_new) return false;
	q_new->param = param;
	q_new->value = value;
	q_new->rest = *q;
	*q = q_new;
	return true;
}

const char *get_query(query_list q, char *param) {
	if(!param) return NULL;
	for(;q;q=q->rest) {
		if(strcmp(param, q->param) == 0) return q->value;
	}
	return NULL;
}

bool contains_query(query_list q, char *param) {
	return (bool)get_query(q, param);
}

static void free_cookies(cookies c) {
	cookies tmp;
	while(c) {
		free(c->name);
		free(c->value);
		tmp = c;
		c = c->rest;
		free(tmp);
	}
}

static bool add_cookie(cookies *c, char *name, char *value) {
	cookies c_new = malloc(sizeof(struct cookie));
	if(!c_new) return false;
	c_new->name = name;
	c_new->value = value;
	c_new->rest = *c;
	*c = c_new;
	return true;
}

static cookies get_cookie_struc(cookies c, char *name) {
	if(!name) return NULL;
	for(;c;c=c->rest) {
		if(!strcmp(name, c->name)) return c;
	}
	return NULL;
}

static bool update_cookie(cookies *c, char *name, char *value) {
	cookies tmp = get_cookie_struc(*c, name);
	if(tmp) {
		free(tmp->value);
		tmp->value = value;
		return true;
	}
	return add_cookie(c, name, value);
}

const char *get_cookie(cookies c, char *name) {
	c = get_cookie_struc(c, name);
	return (c) ? c->value : NULL;
}

static bool close_conn = false;

static bool sendfileall(int out, int in, size_t count, int logfile) {
	size_t sent = 0;
	ssize_t retval;
	while(sent < count) {
		if(sent > 0 && logfile >= 0) dprintf(logfile, "LOG: sent only %zu of %zu bytes so far, sending the rest\n", sent, count);
		retval = sendfile(out, in, NULL, count - sent);
		if(retval < 0) {
			switch(errno) {
			case EAGAIN:
			case ENOMEM:
				if(logfile >= 0) dprintf(logfile, "LOG: Trying again\n");
				continue;
			}
			return false;
		}
		sent += retval;
	}
	return true;
}

static bool sendheaders(int sock, headers h, int flags, int logfile) {
	for(;h;h=h->rest) {
		if(!sendall(sock, h->header, strlen(h->header), flags | MSG_MORE, logfile)) return false;
		if(!sendall(sock, ": ", 2, flags | MSG_MORE, logfile)) return false;
		if(!sendall(sock, h->value, strlen(h->value), flags | MSG_MORE, logfile)) return false;
		if(!sendall(sock, "\r\n", 2, flags | MSG_MORE, logfile)) return false;
	}
	if(!sendall(sock, "\r\n", 2, flags, logfile)) return false;
	return true;
}

enum Method {
	UNSUPPORTED = 0,
	GET,
	HEAD,
	POST,
};
typedef enum Method Method;

static const char *strmeth(Method m) {
	switch(m) {
	case GET:
		return "GET";
	case HEAD:
		return "HEAD";
	case POST:
		return "POST";
	default:
		return NULL;
	}
}

struct request {
	Method method;
	char *target;
	struct HTTPVersion ver;
};
typedef struct request request;

static void free_request(request *re) {
	free(re->target);
	re->target = NULL;
}

static bool parse_request(char *request_line, request *re, int logfile) {
	char *sv = NULL;
	char *meth, *target, *ver, *v1, *v2;
	meth = strtok_r(request_line, " ", &sv);
	if(!meth) return false;
	target = strtok_r(NULL, " ", &sv);
	if(!target) return false;
	ver = strtok_r(NULL, "\r\n", &sv);
	if(!ver) return false;
	sv = NULL;
	char *name = strtok_r(ver, "/", &sv);
	name = (name) ? name : '\0';
	if(strcmp(name, "HTTP")) {
		if(logfile >= 0) dprintf(logfile, "ERROR: Unkown http version name: %s\n", name);
		return false;
	}
	ver = strtok_r(NULL, "", &sv);
	if(!ver) return false;
	sv = NULL;
	v1 = strtok_r(ver, ".", &sv);
	if(!v1) return false;
	v2 = strtok_r(NULL, "", &sv);
	if(!v2) return false;
	long major, minor;
	sv = NULL;
	major = strtol(v1, &sv, 10);
	if(*sv != '\0') return false;
	minor = strtol(v2, &sv, 10);
	if(*sv != '\0') return false;
	char *tmp_target = strdup(target);
	if(!tmp_target) return false;
	re->target = tmp_target;
	re->ver.major = major;
	re->ver.minor = minor;
	Method method = UNSUPPORTED;
	if(!strcmp(meth, "GET")) method = GET;
	if(!strcmp(meth, "HEAD")) method = HEAD;
	if(!strcmp(meth, "POST")) method = POST;
	re->method = method;
	return true;
}

typedef struct pidlist *pidlist;
struct pidlist {
	pid_t pid;
	pidlist rest;
};

static void free_pidlist(pidlist ps) {
	pidlist tmp;
	while(ps) {
		tmp = ps;
		ps = ps->rest;
		free(tmp);
	}
}

static bool add_pid(pidlist *ps, pid_t p) {
	pidlist new_p = malloc(sizeof(struct pidlist));
	if(!new_p) return false;
	new_p->pid = p;
	new_p->rest = *ps;
	*ps = new_p;
	return true;
}

static bool kill_pidlist(pidlist ps, int sig) {
	bool retval = true;
	while(ps) {
		if(kill(ps->pid, sig) < 0) retval = false;
		ps = ps->rest;
	}
	return retval;
}

static bool strong_match(const char *etag1, const char *etag2) {
	return (*etag1 != 'W') && !strcmp(etag1, etag2);
}

static bool weak_match(const char *etag1, const char *etag2) {
	if(*etag1 == 'W') etag1+=2;
	if(*etag2 == 'W') etag2+=2;
	return !strcmp(etag1, etag2);
}

static bool match_any(const char *etag, const char *etags, bool (*cmp)(const char *, const char *)) {
	char *etag_end;
	char tmp;
	bool retval;
	for(;etags;etags = strchr(etag_end, ',')) {
		if(*etags == ',') etags++;
		while(*etags == ' ' || *etags == '\t') etags++;
		etag_end = strchr(etags, '"');
		if(!etag_end) return false; // etags is invalid (this etag is not quoted)
		etag_end = strchr(etag_end + 1, '"');
		if(!etag_end) return false; // etags is invalid (no end quote)
		etag_end++;
		tmp = *etag_end;
		*etag_end = '\0';
		retval = cmp(etag, etags);
		*etag_end = tmp;
		if(retval) return true;
	}
	return false;
}

#define strong_match_any(e, es) match_any(e, es, strong_match)
#define weak_match_any(e, es) match_any(e, es, weak_match)

static bool done = false;

static void exit_loop(int _) {
	done = true;
}

static void chld(int sig, siginfo_t *info, void *uc) {
	if(info->si_code == CLD_EXITED && info->si_status) done = true;
}

static void cleanup(int _) {
	close_conn = true;
}

bool child = false;

#ifndef PORT
#define PORT 80
#endif

// set directory to NULL to serve current directory
// since POST requests are optional, set hls.post_req_handler to NULL if they're not supported
// hls.get_req_handler must be set to a valid pointer, since GET requests are required
bool server(char *directory, struct HTTP_Request_Handlers hls, char *log, int port) {
	if(!hls.get_req_handler) return false;
	if(port < 0) port = PORT;
	int logfile = -1;
	if(log) {
		// open log file
		logfile = open(log, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(logfile < 0) return false;
	}
	struct sigaction siga = {0};
	siga.sa_handler = &exit_loop;
	if(sigaction(SIGINT, &siga, NULL) < 0) {
		if(logfile >= 0) {
			dprintf(logfile, "ERROR: sigaction SIGINT: %s", strerror(errno));
			close(logfile);
		}
		return false;
	}
	if(sigaction(SIGTERM, &siga, NULL) < 0) {
		if(logfile >= 0) {
			dprintf(logfile, "ERROR: sigaction SIGTERM: %s", strerror(errno));
			close(logfile);
		}
		return false;
	}
	if(sigaction(SIGPIPE, &siga, NULL) < 0) {
		if(logfile >= 0) {
			dprintf(logfile, "ERROR: sigaction SIGPIPE: %s", strerror(errno));
			close(logfile);
		}
		return false;
	}
	memset(&siga, 0, sizeof(struct sigaction));
	siga.sa_sigaction = chld;
	siga.sa_flags = SA_NOCLDWAIT | SA_SIGINFO;
	if(sigaction(SIGCHLD, &siga, NULL) < 0) {
		if(logfile >= 0) {
			dprintf(logfile, "Error: sigaction SIGCHLD: %s", strerror(errno));
			close(logfile);
		}
		return false;
	}
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0) {
		if(logfile >= 0) {
			dprintf(logfile, "ERROR: socket: %s", strerror(errno));
			close(logfile);
		}
		return false;
	}
	struct sockaddr_in sad = {0};
	sad.sin_family = AF_INET;
	sad.sin_port = htons((uint16_t)port);
	sad.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(sockfd, (struct sockaddr*)&sad, (socklen_t)sizeof(sad)) < 0) {
		if(logfile >= 0) {
			dprintf(logfile, "ERROR: bind: %s", strerror(errno));
			close(logfile);
		}
		close(sockfd);
		return false;
	}
	if(listen(sockfd, 0) < 0) {
		if(logfile >= 0) {
			dprintf(logfile, "ERROR: listen: %s", strerror(errno));
			close(logfile);
		}
		close(sockfd);
		return false;
	}
	pidlist ps = NULL;
	pid_t p;
	while(!done) {
		struct sockaddr_in cad = {0};
		socklen_t cad_len = sizeof(cad);
		int connfd = accept(sockfd, (struct sockaddr*)&cad, &cad_len);
		if(done) break;
		if(connfd < 0) {
			if(errno != EINTR && logfile >= 0) dprintf(logfile, "ERROR: accept: %s", strerror(errno));
			continue;
		}
		if(logfile >= 0) dprintf(logfile, "LOG: Accepted a connection\n");
		p = fork();
		if(p < 0) {
			if(logfile >= 0) dprintf(logfile, "ERROR: fork: %s", strerror(errno));
			char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
			sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
			close(connfd);
			connfd = -1;
			break;
		}
		if(!p) {
			child = true;
			close(sockfd);
			struct sigaction siga = {0};
			siga.sa_handler = &cleanup;
			if(sigaction(SIGINT, &siga, NULL) < 0) {
				if(logfile >= 0) dprintf(logfile, "ERROR: failed to add signal handler\n");
				char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
				sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
				close(connfd);
				connfd = -1;
				if(logfile >= 0) close(logfile);
				return false;
			}
			if(sigaction(SIGTERM, &siga, NULL) < 0) {
				if(logfile >= 0) dprintf(logfile, "ERROR: failed to add signal handler\n");
				char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
				sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
				close(connfd);
				connfd = -1;
				if(logfile >= 0) close(logfile);
				return false;
			}
			if(sigaction(SIGPIPE, &siga, NULL) < 0) {
				if(logfile >= 0) dprintf(logfile, "ERROR: failed to add signal handler\n");
				char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
				sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
				close(connfd);
				connfd = -1;
				if(logfile >= 0) close(logfile);
				return false;
			}
			siga.sa_handler = SIG_IGN;
			siga.sa_flags = SA_NOCLDWAIT;
			if(sigaction(SIGCHLD, &siga, NULL) < 0) {
				if(logfile >= 0) dprintf(logfile, "ERROR: failed to add signal handler\n");
				char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
				sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
				close(connfd);
				connfd = -1;
				if(logfile >= 0) close(logfile);
				return false;
			}
			bool retval = true;
			while(!close_conn) {
				char *respLine = NULL;
				size_t rspLen = 0;
				int recvd;
				if((recvd = recvline(connfd, &respLine, &rspLen, logfile))) {
					free(respLine);
					if(recvd < 0) {
						if(logfile >= 0) dprintf(logfile, "ERROR: Failed to recv line\n");
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					}
					break;
				}
				if(strlen(respLine) == 2) { // empty line (only contains "\r\n")
					if((recvd = recvline(connfd, &respLine, &rspLen, logfile))) {
						free(respLine);
						if(recvd < 0) {
							if(logfile >= 0) dprintf(logfile, "ERROR: Failed to recv line\n");
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						}
						break;
					}
				}
				request req;
				static const char day[7][4] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
				static const char month[12][4] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
				if(!parse_request(respLine, &req, logfile)) {
					if(logfile >= 0) dprintf(logfile, "ERROR: Failed to parse request: %s\n", respLine);
					free(respLine);
					struct timespec cur_time;
					if(clock_gettime(CLOCK_REALTIME, &cur_time) < 0) {
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						break;
					}
					struct tm tm_current;
					if(!gmtime_r(&(cur_time.tv_sec), &tm_current)) {
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						break;
					}
					char date[30];
					int wr = snprintf(date, 30, "%s, %.2u %s %.4u %.2u:%.2u:%.2u GMT", day[tm_current.tm_wday], tm_current.tm_mday, month[tm_current.tm_mon], tm_current.tm_year + 1900, tm_current.tm_hour, tm_current.tm_min, tm_current.tm_sec);
					if(wr < 0 || wr >= 30) {
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						break;
					}
					date[29] = '\0';
					char *err_resp;
					if(asprintf(&err_resp, "HTTP/1.1 400 Bad Request\r\nDate: %s\r\n\r\n", date) < 0) {
						err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						break;
					}
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					free(err_resp);
					break;
				}
				free(respLine);
				if(req.ver.major != 1 || req.ver.minor != 1) {
					if(logfile >= 0) dprintf(logfile, "ERROR: Version %ld.%ld not supported\n", req.ver.major, req.ver.minor);
					free_request(&req);
					char *err_resp = "HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					break;
				}
				headers h = NULL;
				int rhret = read_headers(connfd, &h, logfile);
				if(rhret) {
					if(logfile >= 0) dprintf(logfile, "ERROR: Failed to read headers\n");
					free_request(&req);
					char *err_resp;
					if(rhret < -1) {
						err_resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
					} else if(rhret < 0) {
						err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						retval = false;
					}
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					break;
				}
				const char *close_str = get_header(h, "Connection");
				close_conn |= close_str && !strcmp(close_str, "close");
				int status;
				char *reason = NULL;
				char *type = NULL;
				int content_fd = -1;
				size_t content_len = 0;
				struct timespec ctime;
				char *etag = NULL;
				headers hdrs = h;
				if(logfile >= 0) dprintf(logfile, "LOG: %s %s\n", strmeth(req.method), req.target);
				char *sv_q = NULL, *sv_frag = NULL;
				char *target = strdup(req.target);
				if(!target) {
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				target = strtok_r(target, "#", &sv_frag);
				target = strtok_r(target, "?", &sv_q);
				char *tmp_target = NULL;
				if(!url_decode(target, &tmp_target, 0)) {
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					free(target);
					break;
				}
				char *old_target = target;
				target = tmp_target;
				char *par, *sv = NULL, *val = NULL;
				query_list q = NULL;
				for(char *query_str = strtok_r(NULL, "&", &sv_q); query_str; query_str = strtok_r(NULL, "&", &sv_q)) {
					sv = NULL;
					par = strtok_r(query_str, "=", &sv);
					if(!par) {
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						free(target);
						free(old_target);
						free_query(q);
						break;
					}
					par = strdup(par);
					if(!par) {
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						free(target);
						free(old_target);
						free_query(q);
						break;
					}
					val = strtok_r(NULL, "", &sv);
					if(!val) val = "";
					val = strdup(val);
					if(!val) {
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						free(target);
						free(old_target);
						free_query(q);
						free(par);
						break;
					}
					if(!add_query(&q, par, val)) {
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						free(target);
						free(old_target);
						free_query(q);
						free(par);
						free(val);
						break;
					}
				}
				free(old_target);
				cookies c = NULL;
				const char *c_tmp = get_header(hdrs, "Cookie");
				if(c_tmp) {
					char *cookie_hdr = strdup(c_tmp);
					if(!cookie_hdr) {
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						free(target);
						free_query(q);
						break;
					}
					sv = NULL;
					val = NULL;
					char *nam = NULL, *sv2 = NULL;
					for(char *cookie_str = strtok_r(cookie_hdr, ";", &sv); cookie_str; cookie_str = strtok_r(NULL, ";", &sv)) {
						if(*cookie_str == ' ') cookie_str++;
						sv2 = NULL;
						nam = strtok_r(cookie_str, "=", &sv2);
						if(!nam) {
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
							retval = false;
							free_request(&req);
							free_headers(h);
							free(target);
							free_query(q);
							free_cookies(c);
							free(cookie_hdr);
							break;
						}
						nam = strdup(nam);
						if(!nam) {
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
							retval = false;
							free_request(&req);
							free_headers(h);
							free(target);
							free_query(q);
							free_cookies(c);
							free(cookie_hdr);
							break;
						}
						val = strtok_r(NULL, "", &sv2);
						if(!val) val = "";
						val = strdup(val);
						if(!val) {
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
							retval = false;
							free_request(&req);
							free_headers(h);
							free(target);
							free_query(q);
							free_cookies(c);
							free(cookie_hdr);
							free(nam);
							break;
						}
						if(!update_cookie(&c, nam, val)) {
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
							retval = false;
							free_request(&req);
							free_headers(h);
							free(target);
							free_query(q);
							free_cookies(c);
							free(cookie_hdr);
							free(nam);
							free(val);
							break;
						}
					}
					free(cookie_hdr);
				}
				switch(req.method) {
				case HEAD:
				case GET:
					{
						const char *value;
						if(!(value = get_header(h, "Expect")) || strcmp(value, "100-continue")) {
							if((value = get_header(h, "Transfer-Encoding")) && *value) {
								if(strcmp(value, "chunked")) {
									if(logfile >= 0) dprintf(logfile, "ERROR: transfer coding(s) not supported (only chunked is supported): %s\n", value);
									char *err_resp = "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n";
									sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
									retval = false;
									close_conn = true;
									free_request(&req);
									free_headers(h);
									free(target);
									free_query(q);
									free_cookies(c);
									continue;
								}
								// chunked
								if((recvd = read_chunked(sockfd, NULL, NULL, true, logfile))) {
									if(recvd < 0) {
										char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
										sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
										retval = false;
									}
									close_conn = true;
									free_request(&req);
									free_headers(h);
									free(target);
									free_query(q);
									free_cookies(c);
									continue;
								}
							} else if((value = get_header(h, "Content-Length"))) {
								uintmax_t size = strtoumax(value, NULL, 10);
								ssize_t srcvd;
								if((srcvd = discard(connfd, size, logfile)) < (intmax_t)size) {
									if(recvd < 0) {
										char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
										sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
										retval = false;
									}
									close_conn = true;
									free_request(&req);
									free_headers(h);
									free(target);
									free_query(q);
									free_cookies(c);
									continue;
								}
							}
						}
						status = hls.get_req_handler(target, q, directory, &hdrs, c, &reason, &type, &content_fd, &content_len, &ctime, &etag);
						break;
					}
				case POST:
					if(hls.post_req_handler) {
						char *req_body = NULL; // request body
						size_t req_size = 0;
						const char *value;
						if((value = get_header(h, "Expect")) && !strcmp(value, "100-continue")) {
							// send 100-continue
							char *resp = "HTTP/1.1 100 Continue\r\n\r\n";
							if(!sendall(connfd, resp, strlen(resp), MSG_NOSIGNAL, logfile)) {
								retval = false;
								close_conn = true;
								free_request(&req);
								free_headers(h);
								free(target);
								free_query(q);
								free_cookies(c);
								continue;
							}
						}
						if((value = get_header(h, "Transfer-Encoding")) && *value) {
							if(strcmp(value, "chunked")) {
								if(logfile >= 0) dprintf(logfile, "ERROR: transfer coding(s) not supported (only chunked is supported): %s\n", value);
								char *err_resp = "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n";
								sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
								retval = false;
								close_conn = true;
								free_request(&req);
								free_headers(h);
								free(target);
								free_query(q);
								free_cookies(c);
								continue;
							}
							// chunked
							if((recvd = read_chunked(connfd, &req_body, &req_size, false, logfile))) {
								if(recvd < 0) {
									char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
									sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
									retval = false;
								}
								close_conn = true;
								free_request(&req);
								free_headers(h);
								free(target);
								free_query(q);
								free_cookies(c);
								continue;
							}
						} else if((value = get_header(h, "Content-Length"))) {
							if(sscanf(value, "%zu", &req_size) < 1) {
								char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
								sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
								close_conn = true;
								retval = false;
								free_request(&req);
								free_headers(h);
								free(target);
								free_query(q);
								free_cookies(c);
								continue;
							}
							req_body = malloc(req_size);
							if(!req_body) {
								char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
								sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
								close_conn = true;
								retval = false;
								free_request(&req);
								free_headers(h);
								free(target);
								free_query(q);
								free_cookies(c);
								continue;
							}
							int recvd;
							if((recvd = recvall(connfd, req_body, req_size, MSG_NOSIGNAL, logfile))) {
								free(req_body);
								if(recvd < 0) {
									char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
									sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
									retval = false;
								}
								close_conn = true;
								free_request(&req);
								free_headers(h);
								free(target);
								free_query(q);
								free_cookies(c);
								continue;
							}
						}
						// read request body into req_body
						status = hls.post_req_handler(target, q, directory, req_body, req_size, &hdrs, c, &reason, &type, &content_fd, &content_len, &ctime, &etag);
						free(req_body);
						break;
					}
				default:
					if(logfile >= 0) dprintf(logfile, "ERROR: Unsupported method\n");
					char *err_resp = "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					close_conn = true;
					retval = false;
					free_request(&req);
					free_headers(h);
					free(target);
					free_query(q);
					free_cookies(c);
					continue;
				}
				free(target);
				free_query(q);
				free_cookies(c);
				struct timespec cur_time;
				if(clock_gettime(CLOCK_REALTIME, &cur_time) < 0) {
					free(type);
					free(etag);
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				struct tm cur_tm;
				if(!gmtime_r(&(cur_time.tv_sec), &cur_tm)) {
					free(type);
					free(etag);
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				char date[30];
				int wr = snprintf(date, 30, "%s, %.2u %s %.4u %.2u:%.2u:%.2u GMT", day[cur_tm.tm_wday], cur_tm.tm_mday, month[cur_tm.tm_mon], cur_tm.tm_year + 1900, cur_tm.tm_hour, cur_tm.tm_min, cur_tm.tm_sec);
				if(wr < 0 || wr >= 30) {
					free(type);
					free(etag);
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				date[29] = '\0';
				const char *value = get_header(h, "Host");
				char *hsvp = NULL, *v2 = NULL;
				if(!value || !(v2 = strdup(value)) || !(v2 = strtok_r(v2, ":", &hsvp)) || !*v2) {
					if(value && logfile >= 0) dprintf(logfile, "ERROR: Invalid hostname: %s\n", value);
					status = 400;
					reason = "Bad Request";
					free_headers(hdrs);
					hdrs = NULL;
					content_len = 0;
				}
				free(v2);
				if(status < 100 || status >= 600 || hdrs == h || !reason || (content_len > 0 && content_fd < 0) || (content_len > 0 && !type)) {
					status = 500;
					reason = "Internal Server Error";
					free_headers(hdrs);
					hdrs = NULL;
					content_len = 0;
				}
				if(status < 200 || status == 204) content_len = 0;
				close_conn |= (status >= 500);
				if(close_conn && !update_header(&hdrs, strdup("Connection"), strdup("close"))) {
					if(logfile >= 0) dprintf(logfile, "ERROR: Failed to add header\n");
					free(type);
					free(etag);
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				if((status < 500) && !update_header(&hdrs, strdup("Date"), strdup(date))) {
					if(logfile >= 0) dprintf(logfile, "ERROR: Failed to add header\n");
					free(type);
					free(etag);
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				if(content_len > 0) {
					if(!update_header(&hdrs, strdup("Content-Type"), type)) {
						if(logfile >= 0) dprintf(logfile, "ERROR: Failed to add header\n");
						free(type);
						free(etag);
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
				} else {
					free(type);
				}
				if(status >= 400) {
					char *respLine;
					free(etag);
					if(asprintf(&respLine, "HTTP/1.1 %d %s\r\nContent-Length: %zu\r\n", status, reason, content_len) < 0) {
						if(logfile >= 0) dprintf(logfile, "ERROR: Failed to create response status line\n");
						free_headers(hdrs);
						if(content_fd >= 0) close(content_fd);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					if(!sendall(connfd, respLine, strlen(respLine), MSG_NOSIGNAL | ((hdrs) ? MSG_MORE : 0), logfile)) {
						if(logfile >= 0) dprintf(logfile, "ERROR: Failed to send response status line\n");
						free_headers(hdrs);
						if(content_fd >= 0) close(content_fd);
						free(respLine);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					free(respLine);
					if(!sendheaders(connfd, hdrs, MSG_NOSIGNAL | ((content_len > 0) ? MSG_MORE : 0), logfile)) {
						if(logfile >= 0) dprintf(logfile, "ERROR: Failed to send response status line\n");
						free_headers(hdrs);
						if(content_fd >= 0) close(content_fd);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					free_headers(hdrs);
					retval = (status < 500);
					if(content_len > 0 && !sendfileall(connfd, content_fd, content_len, logfile)) {
						if(logfile >= 0) dprintf(logfile, "ERROR: Failed to send response body\n");
						retval = false;
						close_conn = true;
					}
					if(content_fd >= 0) close(content_fd);
					free_request(&req);
					free_headers(h);
					continue;
				}
				struct tm tm = {0};
				if(!gmtime_r(&ctime.tv_sec, &tm)) {
					free(etag);
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				char last_modified[30];
				wr = snprintf(last_modified, 30, "%s, %.2u %s %.4u %.2u:%.2u:%.2u GMT", day[tm.tm_wday], tm.tm_mday, month[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
				if(wr < 0 || wr >= 30) {
					free(etag);
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				last_modified[29] = '\0';
				if(!update_header(&hdrs, strdup("Last-Modified"), strdup(last_modified))) {
					free(etag);
					if(logfile >= 0) dprintf(logfile, "ERROR: Failed to add header\n");
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				if(content_len > 0 && etag && !update_header(&hdrs, strdup("ETag"), etag)) {
					free(etag);
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				if((value = get_header(h, "If-Match"))) {
					if((*value == '*') ? (status == 404) : ((etag) ? !strong_match_any(etag, value) : true)) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *resp;
						if(asprintf(&resp, "HTTP/1.1 412 Precondition Failed\r\nDate: %s\r\n\r\n", date) < 0) {
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
							retval = false;
							free_request(&req);
							free_headers(h);
							break;
						}
						sendall(connfd, resp, strlen(resp), MSG_NOSIGNAL, logfile);
						free(resp);
						free_request(&req);
						free_headers(h);
						continue;
					}
				} else if((value = get_header(h, "If-Unmodified-Since"))) {
					struct tm tm2 = {0};
					char mn[3];
					if(!sscanf(value, "%*3c, %2d %3c %4d %2d:%2d:%2d GMT", &tm2.tm_mday, mn, &tm2.tm_year, &tm2.tm_hour, &tm2.tm_min, &tm2.tm_sec)) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					int i;
					for(i = 0; i < 12; i++) {
						if(mn[0] != month[i][0]) continue;
						if(mn[1] != month[i][1]) continue;
						if(mn[2] != month[i][2]) continue;
						break;
					}
					if(i == 12) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					tm2.tm_mon = i;
					tm2.tm_year -= 1900;
					tm2.tm_gmtoff = 0;
					tm2.tm_zone = "UTC";
					tm2.tm_wday = -1;
					time_t time = mktime(&tm2);
					if(tm2.tm_wday == -1) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					if(ctime.tv_sec > time) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *resp;
						if(asprintf(&resp, "HTTP/1.1 412 Precondition Failed\r\nDate: %s\r\n\r\n", date) < 0) {
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
							retval = false;
							free_request(&req);
							free_headers(h);
							break;
						}
						sendall(connfd, resp, strlen(resp), MSG_NOSIGNAL, logfile);
						free(resp);
						free_request(&req);
						free_headers(h);
						continue;
					}
				}
				if((value = get_header(h, "If-None-Match"))) {
					if((*value == '*') ? (status != 404) : ((etag) ? weak_match_any(etag, value) : false)) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *resp = NULL;
						if(asprintf(&resp, "HTTP/1.1 304 Not Modified\r\nDate: %s%s%s\r\n\r\n", date, (etag) ? "\r\nETag: " : "", (etag) ? etag : "") < 0) {
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
							retval = false;
							free_request(&req);
							free_headers(h);
							break;
						}
						sendall(connfd, resp, strlen(resp), MSG_NOSIGNAL, logfile);
						free(resp);
						free_request(&req);
						free_headers(h);
						continue;
					}
				} else if((value = get_header(h, "If-Modified-Since"))) {
					struct tm tm2 = {0};
					char mn[3];
					if(!sscanf(value, "%*3c, %2d %3c %4d %2d:%2d:%2d GMT", &tm2.tm_mday, mn, &tm2.tm_year, &tm2.tm_hour, &tm2.tm_min, &tm2.tm_sec)) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					int i;
					for(i = 0; i < 12; i++) {
						if(mn[0] != month[i][0]) continue;
						if(mn[1] != month[i][1]) continue;
						if(mn[2] != month[i][2]) continue;
						break;
					}
					if(i == 12) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					tm2.tm_mon = i;
					tm2.tm_year -= 1900;
					tm2.tm_gmtoff = 0;
					tm2.tm_zone = "UTC";
					tm2.tm_wday = -1;
					time_t time = mktime(&tm2);
					if(tm2.tm_wday == -1) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					if(ctime.tv_sec <= time) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *resp;
						if(asprintf(&resp, "HTTP/1.1 304 Not Modified\r\nDate: %s%s%s\r\n\r\n", date, (etag) ? "\r\nETag: " : "", (etag) ? etag : "") < 0) {
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
							retval = false;
							free_request(&req);
							free_headers(h);
							break;
						}
						sendall(connfd, resp, strlen(resp), MSG_NOSIGNAL, logfile);
						free(resp);
						free_request(&req);
						free_headers(h);
						continue;
					}
				}
				bool range_request = false;
				size_t start = 0;
				size_t end = content_len - 1;
				if(content_len > 0 && (req.method == GET || req.method == HEAD) && contains_header(h, "Range")) {
					char *range = strdup(get_header(h, "Range"));
					if(!range) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					if(logfile >= 0) dprintf(logfile, "LOG: Range: %s\n", range);
					char *sv = NULL;
					char *token = strtok_r(range, "=", &sv);
					if(!token) {
						free(range);
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						free_request(&req);
						free_headers(h);
						continue;
					} else if(!strcmp(token, "bytes")) {
						token = strtok_r(NULL, "", &sv);
						if(token) {
							if(strchr(token, ',')) {
								// multiple ranges
								// combines the ranges into a single range for now
								// TODO generate a multipart response instead
								end = 0;
								start = content_len;
								sv = NULL;
								char *sv2 = NULL;
								token = strtok_r(token, ",", &sv);
								while(token) {
									size_t tmp_start, tmp_end;
									if(token[0] == '-') {
										token++;
										tmp_end = content_len - 1;
										size_t val = strtoul(token, NULL, 10);
										tmp_start = (val > content_len) ? 0 : content_len - val;
									} else {
										token = strtok_r(token, "-", &sv2);
										tmp_start = strtoul(token, NULL, 10);
										token = strtok_r(NULL, "", &sv2);
										if(token) token = trim(token);
										tmp_end = (token && *(token)) ? strtoul(token, NULL, 10) : content_len - 1;
										if(tmp_end >= content_len) tmp_end = content_len - 1;
									}
									if(tmp_end > end) end = tmp_end;
									if(tmp_start < start) start = tmp_start;
									token = strtok_r(NULL, ",", &sv);
								}
							}
							// single range
							sv = NULL;
							if(token[0] == '-') {
								token = strtok_r(token, "-", &sv);
								size_t val = strtoul(token, NULL, 10);
								start = (val > content_len) ? 0 : content_len - val;
							} else {
								token = strtok_r(token, "-", &sv);
								start = strtoul(token, NULL, 10);
								token = strtok_r(NULL, "", &sv);
								if(token) token = trim(token);
								end = (token && *(token)) ? strtoul(token, NULL, 10) : end;
								if(end >= content_len) end = content_len - 1;
							}
						}
					}
					free(range);
					range = NULL;
					range_request = true;
					if((value = get_header(h, "If-Range"))) {
						range_request = (value[0] == '"' || value[2] == '"') ? ((etag) ? strong_match(etag, value) : false) : false;
					}
					size_t partial_len = end + 1 - start;
					if(partial_len <= 0) {
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = NULL;
						if(asprintf(&err_resp, "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */%zu\r\nDate: %s\r\n\r\n", content_len, date) < 0) {
							err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							retval = false;
						}
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						if(retval) free(err_resp);
						free_request(&req);
						free_headers(h);
						if(retval) continue;
						break;
					}
					if(status == 200) {
						status = 206;
						reason = "Partial Content";
					}
					if(asprintf(&range, "bytes %jd-%jd/%zu", start, end, content_len) < 0) {
						if(logfile >= 0) dprintf(logfile, "ERROR: Failed to create range header");
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					if(!update_header(&hdrs, strdup("Content-Range"), range)) {
						if(logfile >= 0) dprintf(logfile, "ERROR: Failed to create range header");
						if(content_fd >= 0) close(content_fd);
						free_headers(hdrs);
						free(range);
						char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
						sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
						retval = false;
						free_request(&req);
						free_headers(h);
						break;
					}
					content_len = partial_len;
				}
				char *resp;
				if(asprintf(&resp, "HTTP/1.1 %d %s\r\nContent-Length: %zu\r\n", status, reason, content_len) < 0) {
					if(logfile >= 0) dprintf(logfile, "ERROR: Failed to create headers\n");
					if(content_fd >= 0) close(content_fd);
					free_headers(hdrs);
					char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
					sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				if(req.method == GET && range_request) {
					if(lseek(content_fd, start, SEEK_CUR) < 0) {
						if(errno == ESPIPE) {
							if(discard(content_fd, start, logfile) < (ssize_t)start) {
								free(resp);
								free_headers(hdrs);
								if(content_fd >= 0) close(content_fd);
								char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
								sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
								retval = false;
								free_request(&req);
								free_headers(h);
								break;
							}
						} else {
							free(resp);
							free_headers(hdrs);
							if(content_fd >= 0) close(content_fd);
							char *err_resp = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
							sendall(connfd, err_resp, strlen(err_resp), MSG_NOSIGNAL, logfile);
							retval = false;
							free_request(&req);
							free_headers(h);
							break;
						}
					}
				}
				if(!sendall(connfd, resp, strlen(resp), MSG_NOSIGNAL | MSG_MORE, logfile)) {
					if(logfile >= 0) dprintf(logfile, "ERROR: Failed to send headers\n");
					free(resp);
					free_headers(hdrs);
					if(content_fd >= 0) close(content_fd);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				free(resp);
				if(!sendheaders(connfd, hdrs, MSG_NOSIGNAL | ((req.method != HEAD && content_len > 0) ? MSG_MORE : 0), logfile)) {
					if(logfile >= 0) dprintf(logfile, "ERROR: Failed to send headers\n");
					free_headers(hdrs);
					if(content_fd >= 0) close(content_fd);
					retval = false;
					free_request(&req);
					free_headers(h);
					break;
				}
				free_headers(hdrs);
				if(req.method != HEAD && content_len > 0) {
					if(!sendfileall(connfd, content_fd, content_len, logfile)) {
						if(errno == EINVAL) {
							ssize_t rv;
							while((rv = splice(content_fd, NULL, connfd, NULL, content_len, SPLICE_F_MOVE)) < content_len) {
								if(rv == 0) {
									close_conn = true;
									retval = false;
									break;
								}
								if(rv < 0) {
									switch(errno) {
									case EAGAIN:
									case ENOMEM:
										continue;
									}
									close_conn = true;
									retval = false;
									break;
								}
								content_len -= rv;
							}
						} else {
							if(logfile >= 0) dprintf(logfile, "ERROR: Failed to send response body (%d)\n", errno);
							close_conn = true;
						}
					}
				}
				if(content_fd >= 0) close(content_fd);
				free_request(&req);
				free_headers(h);
			}
			close(connfd);
			connfd = -1;
			if(logfile >= 0) close(logfile);
			return retval;
		} else {
			close(connfd);
			if(!add_pid(&ps, p)) {
				if(logfile >= 0) dprintf(logfile, "Could not add pid\n");
				done = true;
			}
			if(logfile >= 0) dprintf(logfile, "LOG: pid: %d\n", p);
			p = 0;
		}
	}
	if(p > 0) kill(p, SIGTERM);
	kill_pidlist(ps, SIGTERM);
	free_pidlist(ps);
	if(logfile >= 0) close(logfile);
	if(close(sockfd) < 0) {
		if(logfile >= 0) dprintf(logfile, "ERROR: close: %s", strerror(errno));
		return false;
	}
	return true;
}
