/*
 * TCP In-Path Bandwidth Monitor
 *
 * Copyright (C) 2023-2024, Naveen Albert
 *
 */

/*! \file
 *
 * \brief TCP In-Path Bandwidth Monitor
 *
 * \author Naveen Albert
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <getopt.h>

#include <tcpinfo.h>

#define DATA_SIZE 1400
#define NUM_LOOPS 250

static void *handler(void *varg)
{
	char *data;
	int i;
	struct tcp_session *tcp = varg;

	data = malloc(DATA_SIZE);
	if (!data) {
		return NULL;
	}

	/* Rotating data to avoid compression */
	/* Chunk writes in blocks <= 1460 */
	for (i = 0; i < DATA_SIZE; i++) {
		data[i] = i % 26 + 'a';
	}
	tcp_write(tcp, data, DATA_SIZE);
	for (i = 0; i < NUM_LOOPS; i++) {
		tcp_write(tcp, data, DATA_SIZE);
		if (tcp_speed_converged(tcp)) {
			fprintf(stderr, "RTT has converged, speed is %f!\n", tcp_speed(tcp));
			break;
		}
	}
	tcp_write(tcp, "123", 3);
	free(data);

	fprintf(stderr, "All done with this connection\n");
	tcp_close(tcp);
	tcp_destroy(tcp);

	return NULL;
}

static int listen_port = -1;
static int listen_local = 0;
static int debug_level = 0;

static int parse_options(int argc, char *argv[])
{
	static const char *getopt_settings = "lpv";
	int c;

	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case 'l':
			listen_local = 1;
			break;
		case 'p':
			listen_port = atoi(argv[optind++]);
			break;
		case 'v':
			debug_level++;
			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", c);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct sockaddr_in sinaddr;
	socklen_t len;
	int sfd, res;
	int sock;
	const int enable = 1;

	if (parse_options(argc, argv)) {
		return -1;
	} else if (listen_port == -1) {
		fprintf(stderr, "Must specify a port: tcpserver -p <port>\n");
		return -1;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "Unable to create TCP socket: %s\n", strerror(errno));
		return -1;
	}

	/* Allow reuse so we can rerun quickly */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		fprintf(stderr, "Unable to create setsockopt: %s\n", strerror(errno));
		return -1;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
		fprintf(stderr, "Unable to create setsockopt: %s\n", strerror(errno));
		return -1;
	}

	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_addr.s_addr = listen_local ? INADDR_LOOPBACK : INADDR_ANY;
	sinaddr.sin_port = htons(listen_port);

	if (bind(sock, (struct sockaddr *) &sinaddr, sizeof(sinaddr))) {
		fprintf(stderr, "Unable to bind TCP socket to port %d: %s\n", listen_port, strerror(errno));
		close(sock);
		return -1;
	}

	if (listen(sock, 2) < 0) {
		fprintf(stderr, "Unable to listen on TCP socket on port %d: %s\n", listen_port, strerror(errno));
		close(sock);
		return -1;
	}

	fprintf(stderr, "Listening on port %d\n", listen_port);

	for (;;) {
		pthread_attr_t attr;
		pthread_t thread;
		struct tcp_session *tcp;
		sfd = accept(sock, (struct sockaddr *) &sinaddr, &len);
		if (sfd < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "accept returned %d: %s\n", sfd, strerror(errno));
				break;
			}
			continue;
		}

		fprintf(stderr, "New connection on fd %d\n", sfd);

		tcp = tcp_create(sfd, 1);
		if (!tcp) {
			close(sfd);
			continue;
		}
		if (tcp_open_log(tcp, NULL)) {
			fprintf(stderr, "tcp_open_log failed: %s\n", strerror(errno));
			tcp_close(tcp);
			tcp_destroy(tcp);
			continue;
		}

		/* Make the thread detached, since we're not going to join it, ever */
		pthread_attr_init(&attr);
		res = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (res) {
			fprintf(stderr, "pthread_attr_setdetachstate: %s\n", strerror(res));
			close(sfd);
			continue;
		}
		if (pthread_create(&thread, &attr, handler, tcp)) {
			fprintf(stderr, "pthread_create failed: %s\n", strerror(errno));
			close(sfd);
		}
	}

	close(sock);
	fprintf(stderr, "Listener thread has exited\n");
}
