/*
 * libtcpinfo
 *
 * TCP In-Path Bandwidth Monitoring Library for Linux
 *
 * Copyright (C) 2023-2024, Naveen Albert
 *
 */

/*! \file
 *
 * \brief TCP In-Path Bandwidth Monitoring Library for Linux
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
#include <assert.h>

#include <sys/sendfile.h>

#include <time.h>

#define SOL_TCP 6 /* TCP level */

#include <linux/tcp.h>

#include "tcpinfo.h"

/* == Library parameters */

/* Poll connection stats every 100 ms, at most */
#define TCP_WRITE_POLL_MS 100

#define NUM_RTT_POINTS 5

/* Broadband threshold */
#define THRESHOLD_B 1536000

#define THRESHOLD_LOSS_INCREASE_FACTOR 30.0
#define THRESHOLD_FLAT_SLOPE 0.00001

/* This is the limit for select(), anyways */
#define MAX_FDS 1024

enum tcp_speed_state {
	STATE_STARTED = 0,
	STATE_RTT_FLAT,					/*!< Flat */
	STATE_RTT_INCREASING,			/*!< Definitely increasing */
	STATE_RTT_INCREASING1,			/*!< Started decreasing */
	STATE_RTT_DECREASING,			/*!< Definitely decreasing */
	STATE_RTT_CONVERGED,			/*!< Converged */
	STATE_RTT_FLUCTUATING,			/*!< Post-convergence */
};

struct tcp_session {
	int fd;							/*!< TCP socket file descriptor */
	struct pollfd pfd;
	FILE *fp;
	int round;						/*!< Round number (number of measurements made) */
	unsigned long total_sec;		/*!< Total seconds */
	unsigned long total_ns;			/*!< Total nanoseconds */
	size_t total_bytes;				/*!< Total number of bytes written */
	unsigned int unbuffered:1;		/*!< Nagle's algorithm disabled? */
	/* Calculation info */
	unsigned int last_rtt1;
	int last_rtt_change2;
	int last_rtt_change1;
	int rtt[NUM_RTT_POINTS];
	enum tcp_speed_state state;
	double last_calc_bps;
	double speed;
	unsigned int converged:1;		/*!< Converged to a result */
	unsigned int is_broadband:1;
};

static struct tcp_session *sessions[MAX_FDS];
static char fds_valid[MAX_FDS]; /* 0 if not valid, 1 if valid */

int tcp_speed_converged(struct tcp_session *tcp)
{
	return tcp->converged;
}

int tcp_speed_is_broadband(struct tcp_session *tcp)
{
	return tcp->is_broadband;
}

double tcp_speed(struct tcp_session *tcp)
{
	return tcp->speed;
}

size_t tcp_bytes_sent(struct tcp_session *tcp)
{
	return tcp->total_bytes;
}

/* Calculate slope from datapoints using curve fitting:
 * Simplified calculation based on:
 * https://www.bragitoff.com/2018/05/linear-fitting-c-program/
 * https://web.iitd.ac.in/~pmvs/courses/mel705/curvefitting.pdf
 */

static double calc_slope(int n, int x[])
{
	int i;
	double slope;
	int sumXY = 0, sumX = 0, sumX2 = 0, sumY = 0;

	for (i = 0; i < n; i++) {
		int y = i + 1;
		sumXY += x[i] * y;
		sumX += x[i];
		sumY += y;
		sumX2 += (x[i] * x[i]);
	}

	sumXY /= n;
	sumX /= n;
	sumY /= n;
	sumX2 /= n;

	/* No floating point operations are done until this point,
	 * making this calculation reasonably fast. */
	slope = (1.0 * sumXY - sumX * sumY) / (1.0 * sumX2 - sumX * sumX);
	return slope;
}

/*! \brief Calculate converged speed and handle state machine */
static inline void process_conn_state(struct tcp_session *tcp, struct tcp_info *tcpinfo, double delivery_bps, double calc_bps, struct timespec *restrict delta)
{
	int rtt_change;
	double slope;

	(void) delivery_bps;

	if (!tcp->converged) {
		/* If delivery rate exceeds B, categorize it as broadband */
		if (delivery_bps > THRESHOLD_B) {
			tcp->is_broadband = 1;
			tcp->converged = 1;
			return;
		}

		/* Otherwise, advance the state machine until we converge. */
		switch (tcp->state) {
		case STATE_STARTED:
			tcp->state = STATE_RTT_FLAT;
			break;
		case STATE_RTT_FLAT:
			if (tcpinfo->tcpi_rtt > tcp->last_rtt1) {
				tcp->state = STATE_RTT_INCREASING;
			}
			break;
		case STATE_RTT_INCREASING:
			if (tcpinfo->tcpi_rtt < tcp->last_rtt1) {
				/* RTT has started to decrease. */
				tcp->state = STATE_RTT_INCREASING1;
			}
			break;
		case STATE_RTT_INCREASING1:
			if (tcpinfo->tcpi_rtt < tcp->last_rtt1) {
				/* RTT continues to decrease */
				tcp->state = STATE_RTT_DECREASING;
			} else if (tcpinfo->tcpi_rtt > tcp->last_rtt1) {
				/* Increased, so go back to increasing */
				tcp->state = STATE_RTT_INCREASING;
			}
			break;
		case STATE_RTT_DECREASING:
			/* Wait until we're relatively flat.
			 * Calculate and keep track of the instantaneous change in RTT
			 * (first derivative) */
			rtt_change = tcpinfo->tcpi_rtt - tcp->last_rtt1;
			if (rtt_change > 0) {
				/* RTT just went up. If it went up a lot, we likely just went straight to the fluctuating state. */
				if (abs(rtt_change) > THRESHOLD_LOSS_INCREASE_FACTOR * abs(tcp->last_rtt_change1) && abs(rtt_change) > THRESHOLD_LOSS_INCREASE_FACTOR * abs(tcp->last_rtt_change2)) {
					tcp->state = STATE_RTT_FLUCTUATING;
					goto converged;
				} else {
					/* Go back to start of decreasing state */
					tcp->state = STATE_RTT_INCREASING1;
				}
			} else if (rtt_change < 0) {
				/* If declines are getting smaller and are already quite small,
				 * then we've probably converged. */
				if (rtt_change <= tcp->last_rtt_change1 && rtt_change < 1) {
					tcp->state = STATE_RTT_CONVERGED;
					goto converged;
				}
			} /* else, ignore constant (no change) */
			if (rtt_change != tcp->last_rtt_change1) {
				tcp->last_rtt_change2 = tcp->last_rtt_change1;
				tcp->last_rtt_change1 = rtt_change;
			}
			/* Fall through */
		case STATE_RTT_CONVERGED:
		case STATE_RTT_FLUCTUATING:
converged:
			slope = calc_slope(NUM_RTT_POINTS, tcp->rtt);
			if (slope < THRESHOLD_FLAT_SLOPE) {
				tcp->speed = tcp->last_calc_bps;
				tcp->converged = 1;
			}
		}
		/* Store the last RTT that was different, since otherwise kernel metrics likely aren't changing */
		if (tcp->last_rtt1 != tcpinfo->tcpi_rtt) {
			memmove(tcp->rtt, tcp->rtt + 1, sizeof(tcp->rtt[0]) * NUM_RTT_POINTS - 1); /* Shift all points left */
			tcp->rtt[NUM_RTT_POINTS - 1] = tcpinfo->tcpi_rtt;
			tcp->last_rtt1 = tcpinfo->tcpi_rtt;
		}
		tcp->last_calc_bps = calc_bps;
	}
}

struct tcp_session *tcp_create(int fd, int unbuffered)
{
	struct tcp_session *tcp = calloc(1, sizeof(*tcp));
	if (tcp) {
		tcp->fd = fd;
		tcp->pfd.events = POLLOUT;
		tcp->pfd.fd = fd;
		if (unbuffered) {
			int enable = 1;
			/* Disable Nagle's Algorithm so writes are sent immediately without being buffered. */
			if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int))) {
				return NULL;
			}
			tcp->unbuffered = 1;
		}
		if (fd >= 0 && fd < MAX_FDS) {
			fds_valid[fd] = 1;
			sessions[fd] = tcp;
		}
	}
	return tcp;
}

int tcp_open_log(struct tcp_session *tcp, const char *logfile)
{
	char logbuf[256];
	if (tcp->fp) {
		/* Log file already open */
		errno = EEXIST;
		return -1;
	}
	if (!logfile) {
		/* Auto-choose a name */
		snprintf(logbuf, sizeof(logbuf), "%lu-%d.csv", time(NULL), tcp->fd);
		logfile = logbuf;
	}
	tcp->fp = fopen(logfile, "a");
	if (!tcp->fp) {
		return -1;
	}
	return 0;
}

struct tcp_session *tcp_session_get(int fd)
{
	struct tcp_session *tcp;

	if (fd < 0 || fd >= MAX_FDS) {
		errno = ERANGE;
		return NULL;
	}
	if (!fds_valid[fd]) {
		errno = EINVAL;
		return NULL;
	}
	tcp = sessions[fd];
	assert(tcp != NULL);
	assert(tcp->fd == fd);
	return tcp;
}

int tcp_close(struct tcp_session *tcp)
{
	int fd = tcp->fd;
	if (fds_valid[tcp->fd]) {
		sessions[tcp->fd] = NULL;
		fds_valid[fd] = 0;
	}
	tcp->fd = -1;
	return close(fd);
}

void tcp_destroy(struct tcp_session *tcp)
{
	if (tcp->fp) {
		fclose(tcp->fp);
		tcp->fp = NULL;
	}
	free(tcp);
}

ssize_t tcp_poll(struct tcp_session *tcp, int ms)
{
	tcp->pfd.revents = 0;
	return poll(&tcp->pfd, 1, ms);
}

ssize_t tcp_read(struct tcp_session *tcp, char *buf, size_t len)
{
	return read(tcp->fd, buf, len);
}

/*!
 * \internal
 * \brief Callback to call after writing or after socket is determined to still be unwritable
 */
static int tcp_post(struct tcp_session *tcp, struct timespec *restrict start)
{
	double delivery_bps, calc_bps;
	struct timespec finish, delta;
	struct tcp_info tcpinfo;
	socklen_t tcp_info_length = sizeof(tcpinfo);

	/* Collect stats every TCP_WRITE_POLL_MS, or after each write */
	if (clock_gettime(CLOCK_REALTIME, &finish)) {
		return -1;
	}

	/* Get current connection properties.
	 * This also encompasses the information we could get using the TIOCOUTQ ioctl. */
	if (getsockopt(tcp->fd, SOL_TCP, TCP_INFO, &tcpinfo, &tcp_info_length)) {
		return -1;
	}

	/* Calculate difference */
	delta.tv_sec = finish.tv_sec - start->tv_sec;
	delta.tv_nsec = finish.tv_nsec - start->tv_nsec;
	if (delta.tv_nsec < 0) {
		delta.tv_nsec += 1000000000;
		delta.tv_sec--;
	}
	tcp->total_ns += delta.tv_nsec;
	if (tcp->total_ns >= 1000000000) {
		tcp->total_sec++;
		tcp->total_ns -= 1000000000;
	}
	tcp->total_sec += delta.tv_sec;

	++tcp->round;
	delivery_bps = tcpinfo.tcpi_delivery_rate * 8;
	calc_bps = (tcpinfo.tcpi_snd_wnd * 8) / (tcpinfo.tcpi_rtt * 1.0 / 1000000);
	if (tcp->fp) {
		fprintf(tcp->fp,
		"%u,%lu.%08lu,%ld,%ld,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
		"%llu,%llu,%u,%llu,%llu,%u,"
		"%f,%f"
		"\r\n",
		tcp->round,
		tcp->total_sec,
		tcp->total_ns,
		delta.tv_sec,
		delta.tv_nsec,
		tcpinfo.tcpi_snd_wscale,
		tcpinfo.tcpi_rcv_wscale,
		tcpinfo.tcpi_snd_mss,
		tcpinfo.tcpi_rcv_mss,
		tcpinfo.tcpi_snd_ssthresh,
		tcpinfo.tcpi_rcv_ssthresh,
		tcpinfo.tcpi_pmtu,		/* MTU (e.g. 1500) */
		tcpinfo.tcpi_advmss,	/* Maximum segment size advertised (e.g. 1460) is max number of bytes per packet. */
		tcpinfo.tcpi_snd_cwnd,	/* Congestion window, as a multiple of MSS */
		(uint32_t) (tcpinfo.tcpi_snd_cwnd * tcpinfo.tcpi_advmss),
		tcpinfo.tcpi_rtt,
		tcpinfo.tcpi_rttvar,
		tcpinfo.tcpi_unacked,
		tcpinfo.tcpi_pacing_rate, tcpinfo.tcpi_bytes_acked, tcpinfo.tcpi_notsent_bytes, tcpinfo.tcpi_delivery_rate, tcpinfo.tcpi_bytes_sent, tcpinfo.tcpi_snd_wnd,
		delivery_bps, calc_bps
		);
	}

	process_conn_state(tcp, &tcpinfo, delivery_bps, calc_bps, &delta);
	return 0;
}

ssize_t tcp_write(struct tcp_session *tcp, const char *buf, size_t len)
{
	const char *pos = buf;
	ssize_t remaining = len;

	while (remaining > 0) {
		ssize_t res = 0;
		struct timespec start;

		/* Don't need absolute time, just the difference */
		if (clock_gettime(CLOCK_REALTIME, &start)) {
			return -1;
		}

		/* Wait a little bit for the socket to become writable.
		 * From the caller's perspective, there is no difference.
		 * However, this allows us to poll the TCP stats in the kernel
		 * periodically instead of just being blocked on a write()
		 * call waiting for there to be enough room in the buffers
		 * to flush the data that the caller is trying to write. */
		tcp->pfd.revents = 0;
		res = poll(&tcp->pfd, 1, TCP_WRITE_POLL_MS);
		if (res < 0) {
			return res;
		}
		if (res > 0) {
			res = write(tcp->fd, pos, remaining);
			if (res <= 0) {
				return res;
			}
			tcp->total_bytes += res;
		}

		if (tcp_post(tcp, &start)) {
			return -1;
		}

		remaining -= (size_t) res;
		pos += res;
	}
	return len; /* All data was successfully written */
}

ssize_t tcp_sendfile(struct tcp_session *tcp, int in_fd, off_t *offset, size_t count)
{
	off_t s_offset;
	size_t len = count;
	ssize_t remaining = count;

	if (!offset) {
		/* Get the current file offset */
		s_offset = lseek(in_fd, 0, SEEK_CUR);
		offset = &s_offset;
	}

	while (remaining > 0) {
		ssize_t res = 0;
		struct timespec start;

		/* Don't need absolute time, just the difference */
		if (clock_gettime(CLOCK_REALTIME, &start)) {
			return -1;
		}

		/* Wait a little bit for the socket to become writable.
		 * From the caller's perspective, there is no difference.
		 * However, this allows us to poll the TCP stats in the kernel
		 * periodically instead of just being blocked on a write()
		 * call waiting for there to be enough room in the buffers
		 * to flush the data that the caller is trying to write. */
		tcp->pfd.revents = 0;
		res = poll(&tcp->pfd, 1, TCP_WRITE_POLL_MS);
		if (res < 0) {
			return res;
		}
		if (res > 0) {
			res = sendfile(tcp->fd, in_fd, offset, remaining);
			if (res <= 0) {
				return res;
			}
			tcp->total_bytes += res;
		}

		if (tcp_post(tcp, &start)) {
			return -1;
		}

		remaining -= (size_t) res;
	}
	return (ssize_t) len; /* All data was successfully written */
}

/* == Abstract I/O functions == */

ssize_t tcp_abstract_write(int fd, const char *buf, size_t len)
{
	struct tcp_session *tcp = tcp_session_get(fd);

	if (!tcp) {
		/* write() called for file descriptor that we're not monitoring.
		 * Just do a normal write. */
		return write(fd, buf, len);
	}
	return tcp_write(tcp, buf, len);
}
