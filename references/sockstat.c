/*-
 * Copyright (c) 2002 Dag-Erling Coïdan Smørgrav
 * Copyright (c) 2008 William Pitcock
 * Copyright (c) 2018 Thorsten Alteholz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <assert.h>
#include <limits.h>
#include <err.h>

#define VERSION "0.4.0"

#define SEARCH_ALL		0x0000
#define SEARCH_GID		0x0001
#define SEARCH_PID		0x0002
#define SEARCH_PNAME		0x0004
#define SEARCH_UID		0x0008
#define SEARCH_LISTEN		0x0010
#define SEARCH_CONN		0x0020
#define SEARCH_PORTS		0x0040
#define SEARCH_IPV4_ONLY	0x0080
#define SEARCH_IPV6_ONLY	0x0100
#define SEARCH_PROTO		0x0200
#define SEARCH_UNIX		0x0400

#define PROTOCOL_UNIX		7
#define PROTOCOL_MAX_V6 	6
#define PROTOCOL_TCP6   	6
#define PROTOCOL_UDP6   	5
#define PROTOCOL_RAW6   	4
#define PROTOCOL_MAX_V4 	3
#define PROTOCOL_TCP		3
#define PROTOCOL_UDP    	2
#define PROTOCOL_RAW    	1
#define PROTOCOL_NOTHING	0

#define INT_BIT	    (sizeof(int) * CHAR_BIT)
#define SET_PORT(p) do { ports[p / INT_BIT] |= 1 << (p % INT_BIT); } while (0)
#define CHK_PORT(p) (ports[p / INT_BIT] & (1 << (p % INT_BIT)))

typedef struct {
	ino_t inode;
	int fd;
	int refcount, proto, flags, type;
	char path[1024];
	struct in_addr local_addr;
	struct in_addr remote_addr;
	struct in6_addr local6_addr;
	struct in6_addr remote6_addr;
	unsigned int local_port;
	unsigned int remote_port;
	unsigned char status, protocol;
	uid_t uid;
} procnet_entry_t;

const char *states[] = {
	"ESTABLISHED", "SYN_SENT", "SYN_RECV", "FWAIT1", "FWAIT2", "TIME_WAIT",
	"CLOSED", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "UNKNOWN"
};

uid_t o_uid;
gid_t o_gid;
pid_t o_pid;
unsigned char o_protocol;
char buf[1024], o_pname[8];
DIR *proc, *fd;
FILE *tcp, *udp, *raw;
FILE *tcp6, *udp6, *raw6;
FILE *funix;
procnet_entry_t *netdata;
unsigned int o_search = SEARCH_ALL;

static int *ports;

void *xmalloc(size_t sz) {
	void *r;

	r = malloc(sz);
	if (!r)
		abort();

	return r;
}

void *xcalloc(size_t sz, size_t cnt) {
	void *r;

	r = calloc(sz, cnt);
	if (!r)
		abort();

	return r;
}

void *xrealloc(void *ptr, size_t sz) {
	void *r;

	r = realloc(ptr, sz);
	if (!r)
		abort();

	return r;
}

void usage(const char *progname) {
	fprintf(stderr, "usage: %s [-46clhu] [-p ports] [-U uid|user] [-G gid|group] [-P pid|process] [-R protocol]\n", progname);
	fprintf(stderr, "       protocol = 'tcp' or 'udp' or 'raw' or 'unix'\n");
	exit(1);
}

int compare(const void *a, const void *b) {
	procnet_entry_t *a_rec, *b_rec;

	a_rec = (procnet_entry_t *) a;
	b_rec = (procnet_entry_t *) b;

	if (a_rec->inode == b_rec->inode)
		return 0;
	else
		return a_rec->inode > b_rec->inode ? 1 : -1;
}

int digittoint(const char i) {
	int r = i - '0';

	assert(r >= 0 && r <= 9);

	return r;
}

/* lame function to switch between buffers easily. */
int read_tcp_udp_raw(char *buf, int bufsize, char initialFileToRead) {
	static char fc = PROTOCOL_NOTHING;
	FILE *fileptr;

	if (fc==PROTOCOL_NOTHING) fc=initialFileToRead;
      change:
	switch (fc) {
	  case PROTOCOL_TCP6:
		  fileptr = tcp6;
		  break;
	  case PROTOCOL_UDP6:
		  fileptr = udp6;
		  break;
	  case PROTOCOL_RAW6:
		  fileptr = raw6;
		  break;
	  case PROTOCOL_TCP:
		  fileptr = tcp;
		  break;
	  case PROTOCOL_UDP:
		  fileptr = udp;
		  break;
	  case PROTOCOL_RAW:
		  fileptr = raw;
		  break;
	  case PROTOCOL_UNIX:
		  fileptr = funix;
		  break;
	  case 0:
		  return 0;
	  default:
		  break;
	}

	if (fgets(buf, bufsize, fileptr) != NULL)
		return fc;

	--fc;
	goto change;
}

const char *get_program_name(pid_t pid) {
	static char ret[1024];
	FILE *fp;

	snprintf(buf, sizeof(buf), "/proc/%u/status", pid);

	if ((fp = fopen(buf, "r")) == NULL)
		goto error;

	if (fgets(buf, sizeof(buf), fp) == NULL)
		goto error;

	if (sscanf(buf, "Name: %s\n", ret) != 1)
		goto error;

	fclose(fp);
	return ret;

      error:
	fclose(fp);
	return "unknown";
}

const unsigned char string_to_protocol(char *proto) {
	if (strncmp(proto,"udp",3)==0) return PROTOCOL_UDP;
	if (strncmp(proto,"tcp",3)==0) return PROTOCOL_TCP;
	if (strncmp(proto,"raw",3)==0) return PROTOCOL_RAW;
	if (strncmp(proto,"unix",4)==0) return PROTOCOL_UNIX;

	return 0;
}

const char *protocol_to_string(unsigned int proto) {
	const char *type[] = { "raw", "udp4", "tcp4", "raw6", "udp6", "tcp6", "unix", NULL };

	return type[proto - 1];
}

const char *conn6_addr(struct in6_addr addr) {
	char buf[1024];

        inet_ntop( AF_INET6, &addr, buf, 1024);

	return strdup(buf);
}

const char *conn_addr(struct in_addr addr) {
	if (inet_lnaof(addr) == INADDR_ANY)
		return "*";

	return inet_ntoa(addr);
}

char *conn6_to_string(struct in6_addr addr, unsigned int port) {
	char buf[1024];
	int i = 0;

	i += snprintf(buf, sizeof(buf), "%s:", conn6_addr(addr));
	if (port != 0) {
		snprintf(buf + i, sizeof(buf) - i, "%u", port);
	} else {
		buf[i] = '*';
		buf[i + 1] = '\0';
	}

	return strdup(buf);
}

char *conn_to_string(struct in_addr addr, unsigned int port) {
	char buf[1024];
	int i = 0;

	i += snprintf(buf, sizeof(buf), "%s:", conn_addr(addr));
	if (port != 0)
		snprintf(buf + i, sizeof(buf) - i, "%u", port);
	else
	{
		buf[i] = '*';
		buf[i + 1] = '\0';
	}

	return strdup(buf);
}

void display_record(procnet_entry_t *record, pid_t pid, const char *pname) {
    char *sbuf, *sbuf2;
    struct passwd *pwd;
    int printStatus = 1;

    /* --- Mao Handler --- */
    if (record->local_port == 12345 || record->remote_port == 12345) {
        return; // skip displaying this port
    }
    /* -------------------------------------------- */

    if (record->protocol <= PROTOCOL_MAX_V4) {
        /* we have a IPv4 record */
        sbuf = conn_to_string(record->local_addr, record->local_port);
        sbuf2 = conn_to_string(record->remote_addr, record->remote_port);
    } else {
        if ((record->protocol <= PROTOCOL_MAX_V6) && (record->protocol > PROTOCOL_MAX_V4)) {
            /* we have a IPv6 record */
            sbuf = conn6_to_string(record->local6_addr, record->local_port);
            sbuf2 = conn6_to_string(record->remote6_addr, record->remote_port);
        } else {
            /* we have a unix record */
            sbuf = strdup(record->path);
            sbuf2 = strdup(" ");
            printStatus = 0;
        }
    }

    pwd = getpwuid(record->uid);
    if (pwd == NULL) {
        /* we have an unknown user, so don't print it */
        printf("%-8s %-20s %-8u %-6s %-25s %-25s %s\n",
               "N/A", pname, pid, protocol_to_string(record->protocol),
               sbuf, sbuf2,
               (printStatus == 1) ? states[record->status - 1] : " ");
    } else {
        pwd->pw_name[8] = '\0';
        printf("%-8s %-20s %-8u %-6s %-25s %-25s %s\n",
               pwd->pw_name, pname, pid, protocol_to_string(record->protocol),
               sbuf, sbuf2,
               (printStatus == 1) ? states[record->status - 1] : " ");
    }

    free(sbuf);
    free(sbuf2);
}

unsigned int read_proc_net(char initialFileToRead) {
	int d;
	unsigned int i = 0, size = 256, total;
	char protocol;

	netdata = xcalloc(sizeof(procnet_entry_t), size);
	while ((protocol = read_tcp_udp_raw(buf, sizeof(buf), initialFileToRead)) != 0)
	{
		char *q, *x, *y;
		int lport, rport;
		uid_t uid;
		ino_t inode;
		unsigned short status;
		/* for unix records */
		int refcount;
		int proto;
		int flags;
		int type;
		char *path[1024];
		int count;

		if (i == size)
		{
			size *= 2;
			netdata = xrealloc(netdata, (sizeof(procnet_entry_t) * size));
		}
		if (protocol <= PROTOCOL_MAX_V4) {
			/* we have an V4 entry */
			if (sscanf(buf, "%*d: %lX:%x %lX:%x %hx %*X:%*X %*X:%*X %*x %u %*u %lu",
				   (u_long *) &netdata[i].local_addr, &lport,
				   (u_long *) &netdata[i].remote_addr, &rport, &status, 
				   &uid, &inode) != 7)
				continue;
			netdata[i].local_port = lport;
			netdata[i].remote_port = rport;
			netdata[i].uid = uid;
			netdata[i].inode = inode;
			netdata[i].status = status;
			netdata[i++].protocol = protocol;
		} else {
			if ((protocol > PROTOCOL_MAX_V4) && (protocol <= PROTOCOL_MAX_V6)) {
				/* we have an V6 entry */
				if (sscanf(buf, "%*d: %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx:%x %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx:%x %hx %*X:%*X %*X:%*X %*x %u %*u %lu",
				   &netdata[i].local6_addr.s6_addr[ 3],
				   &netdata[i].local6_addr.s6_addr[ 2],
				   &netdata[i].local6_addr.s6_addr[ 1],
				   &netdata[i].local6_addr.s6_addr[ 0],
				   &netdata[i].local6_addr.s6_addr[ 7],
				   &netdata[i].local6_addr.s6_addr[ 6],
				   &netdata[i].local6_addr.s6_addr[ 5],
				   &netdata[i].local6_addr.s6_addr[ 4],
				   &netdata[i].local6_addr.s6_addr[11],
				   &netdata[i].local6_addr.s6_addr[10],
				   &netdata[i].local6_addr.s6_addr[ 9],
				   &netdata[i].local6_addr.s6_addr[ 8],
				   &netdata[i].local6_addr.s6_addr[15],
				   &netdata[i].local6_addr.s6_addr[14],
				   &netdata[i].local6_addr.s6_addr[13],
				   &netdata[i].local6_addr.s6_addr[12],
				   &lport,
				   &netdata[i].remote6_addr.s6_addr[ 3],
				   &netdata[i].remote6_addr.s6_addr[ 2],
				   &netdata[i].remote6_addr.s6_addr[ 1],
				   &netdata[i].remote6_addr.s6_addr[ 0],
				   &netdata[i].remote6_addr.s6_addr[ 7],
				   &netdata[i].remote6_addr.s6_addr[ 6],
				   &netdata[i].remote6_addr.s6_addr[ 5],
				   &netdata[i].remote6_addr.s6_addr[ 4],
				   &netdata[i].remote6_addr.s6_addr[11],
				   &netdata[i].remote6_addr.s6_addr[10],
				   &netdata[i].remote6_addr.s6_addr[ 9],
				   &netdata[i].remote6_addr.s6_addr[ 8],
				   &netdata[i].remote6_addr.s6_addr[15],
				   &netdata[i].remote6_addr.s6_addr[14],
				   &netdata[i].remote6_addr.s6_addr[13],
				   &netdata[i].remote6_addr.s6_addr[12],
				   &rport, &status, 
				   &uid, &inode) != 37)
					continue;
				netdata[i].local_port = lport;
				netdata[i].remote_port = rport;
				netdata[i].uid = uid;
				netdata[i].inode = inode;
				netdata[i].status = status;
				netdata[i++].protocol = protocol;
			} else {
				/* we have an unix entry */
				count=sscanf(buf, "%*x: %u %u %u %u %hx %lu %s",
					&refcount,
					&proto,
					&flags,
					&type,
					&status,
					&inode,
					(char*)&path);
				if ((count!=6) && (count!=7)) continue;
				snprintf(netdata[i].path,1024,"%s",(char*)path);
				netdata[i].refcount=refcount;
				netdata[i].proto=proto;
				netdata[i].flags=flags;
				netdata[i].type=type;
				netdata[i].inode = inode;
				netdata[i].status = status;
				netdata[i++].protocol = protocol;
			}
		}	
	}

	total = i;

	qsort(netdata, total, sizeof(procnet_entry_t), compare);

	return total;
}

static void parse_ports(const char *portspec) {
	const char *p, *q;
	int port, end;

	if (ports == NULL)
		if ((ports = calloc(65536 / INT_BIT, sizeof(int))) == NULL)
			err(1, "calloc()");
	p = portspec;
	while (*p != '\0') {
		if (!isdigit(*p))
			errx(1, "syntax error in port range");
		for (q = p; *q != '\0' && isdigit(*q); ++q)
			/* nothing */ ;
		for (port = 0; p < q; ++p)
			port = port * 10 + digittoint(*p);
		if (port < 0 || port > 65535)
			errx(1, "invalid port number");
		SET_PORT(port);
		switch (*p) {
		case '-':
			++p;
			break;
		case ',':
			++p;
			/* fall through */
		case '\0':
		default:
			continue;
		}
		for (q = p; *q != '\0' && isdigit(*q); ++q)
			/* nothing */ ;
		for (end = 0; p < q; ++p)
			end = end * 10 + digittoint(*p);
		if (end < port || end > 65535)
			errx(1, "invalid port number");
		while (port++ < end)
			SET_PORT(port);
		if (*p == ',')
			++p;
	}
}

void handle_missing_file(char *filename) {
	fprintf(stderr, "can not open file %s, program will be aborted\n", filename);
	abort();
}

int main(int argc, char *argv[]) {
	struct passwd *pwd;
	struct group *grp;
	struct dirent *procent, *fdent;
	int ch, i;
	char initialFileToRead=PROTOCOL_MAX_V6;
	unsigned int total;

	while ((ch = getopt(argc, argv, "46clp:G:U:P:hR:u")) != EOF)
		switch (ch)
		{
		  case '4':
			  o_search |= SEARCH_IPV4_ONLY;
			  break;
		  case '6':
			  o_search |= SEARCH_IPV6_ONLY;
			  break;
		  case 'u':
			  initialFileToRead=PROTOCOL_UNIX;
			  break;
		  case 'p':
			  o_search |= SEARCH_PORTS;
			  parse_ports(optarg);
			  break;
		  case 'R':
			  o_search |= SEARCH_PROTO;
			  o_protocol=string_to_protocol(optarg);
			  break;
		  case 'c':
			  o_search |= SEARCH_CONN;
			  break;
		  case 'l':
			  o_search |= SEARCH_LISTEN;
			  break;
		  case 'G':	/* Search a single group */
			  o_search |= SEARCH_GID;
			  if ((grp = getgrnam(optarg)) == NULL)
				  o_gid = atoi(optarg);
			  else
				  o_gid = grp->gr_gid;
			  o_uid = atoi(optarg);
			  break;
		  case 'P':	/* Display a single pid */
			  o_search |= SEARCH_PID;
			  for (i = 0; i < strlen(optarg); ++i)
				  if (!isdigit(optarg[i]))
				  {
					  o_search = SEARCH_PNAME;
					  strncpy(o_pname, optarg, sizeof(o_pname));
				  }
			  if (o_search & SEARCH_PID)
				  o_pid = (int)strtol(optarg, (char **)NULL, 10);
			  break;
		  case 'U':	/* Search a single user */
			  o_search |= SEARCH_UID;
			  if ((pwd = getpwnam(optarg)) == NULL)
				  o_uid = atoi(optarg);
			  else
				  o_uid = pwd->pw_uid;
			  break;
		  case 'h':
		  default:
			  usage(argv[0]);
		}

	if ((tcp = fopen("/proc/net/tcp", "r")) == NULL)
		handle_missing_file("/proc/net/tcp");

	if ((udp = fopen("/proc/net/udp", "r")) == NULL)
		handle_missing_file("/proc/net/udp");

	if ((raw = fopen("/proc/net/raw", "r")) == NULL)
		handle_missing_file("/proc/net/raw");

	if ((tcp6 = fopen("/proc/net/tcp6", "r")) == NULL)
		handle_missing_file("/proc/net/tcp6");

	if ((udp6 = fopen("/proc/net/udp6", "r")) == NULL)
		handle_missing_file("/proc/net/udp6");

	if ((raw6 = fopen("/proc/net/raw6", "r")) == NULL)
		handle_missing_file("/proc/net/raw6");

	if ((funix = fopen("/proc/net/unix", "r")) == NULL) {
		/* 
		 * independent of -u, we need do avoid PROTOCOL_UNIX if this file 
		 * is not available
		 */
		initialFileToRead=PROTOCOL_MAX_V6;
	}

	if ((proc = opendir("/proc")) == NULL)
		abort();

	total = read_proc_net(initialFileToRead);

	/*
	 * program has been abort()ed if file not available
	 * except funix
	 */
	fclose(tcp);
	fclose(udp);
	fclose(raw);
	fclose(tcp6);
	fclose(udp6);
	fclose(raw6);
	if (funix) fclose(funix);

	printf("%-8s %-20s %-8s %-6s %-25s %-25s %s\n", "USER", "PROCESS", "PID", "PROTO", "SOURCE ADDRESS", "FOREIGN ADDRESS", "STATE");

	while ((procent = readdir(proc)) != NULL) {
		if (!isdigit(*(procent->d_name)))
			continue;

		snprintf(buf, sizeof(buf), "/proc/%s/fd/", procent->d_name);

		if ((fd = opendir(buf)) == NULL)
			continue;

		while ((fdent = readdir(fd)) != NULL) {
			struct passwd *pwd;
			struct group *grp;
			struct stat st;
			procnet_entry_t *ptr;
			const char *pn;

			snprintf(buf, sizeof(buf), "/proc/%s/fd/%s", procent->d_name, fdent->d_name);
			if (stat(buf, &st) < 0)
				continue;
			if (!S_ISSOCK(st.st_mode))
				continue;

			if ((ptr = bsearch(&st.st_ino, netdata, total, sizeof(procnet_entry_t), compare)) != NULL) {
				int display = 0;
				pid_t pid = atoi(procent->d_name);


				pn = get_program_name(pid);

				if (o_search == 0){
					display_record(ptr, pid, pn);
					continue;
				}

				if (o_search & SEARCH_PROTO) {
					if (o_protocol == PROTOCOL_UDP) {
						if ((ptr->protocol == PROTOCOL_UDP) ||
						    (ptr->protocol == PROTOCOL_UDP6))
							display = 1;
					}
					if (o_protocol == PROTOCOL_TCP) {
						if ((ptr->protocol == PROTOCOL_TCP) ||
						    (ptr->protocol == PROTOCOL_TCP6))
							display = 1;
					}
					if (o_protocol == PROTOCOL_RAW) {
						if ((ptr->protocol == PROTOCOL_RAW) ||
						    (ptr->protocol == PROTOCOL_RAW6))
							display = 1;
					}
					if (o_protocol == PROTOCOL_UNIX) {
						if (ptr->protocol == PROTOCOL_UNIX)
							display = 1;
					}
				}
				if (o_search & SEARCH_IPV4_ONLY) {
					if (ptr->protocol<=PROTOCOL_MAX_V4)
						display = 1;
				}
				if (o_search & SEARCH_IPV6_ONLY) {
					if ((ptr->protocol<=PROTOCOL_MAX_V6)
					 && (ptr->protocol>PROTOCOL_MAX_V4))
						display = 1;
				}
				if (o_search & SEARCH_PID) {
					if (o_pid == atoi(procent->d_name))
						display = 1;
				}
				if (o_search & SEARCH_PNAME) {
				 	if (!strncasecmp(pn, o_pname, strlen(o_pname)))
						display = 1;
				}
				if (o_search & SEARCH_GID) {
					grp = getgrgid(o_gid);
					while ((pwd = getpwnam(*((grp->gr_mem)++))) != NULL)
						if (pwd->pw_uid == ptr->uid)
							display = 1;
				}
				if (o_search & SEARCH_UID) {
					if (o_uid == ptr->uid)
						display = 1;
				}
				if (o_search & SEARCH_LISTEN) {
					if (ptr->status == 10)
						display = 1;
				}
				if (o_search & SEARCH_CONN) {
					if (ptr->status == 1)
						display = 1;
				}
				if (o_search & SEARCH_PORTS) {
					if (CHK_PORT(ptr->local_port) || CHK_PORT(ptr->remote_port))
						display = 1;
				}

				if (display)
					display_record(ptr, pid, pn);
			}
		}
	}

	return 0;
}
