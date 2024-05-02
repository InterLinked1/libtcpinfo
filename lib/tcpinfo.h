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

struct tcp_session;

/*! \note Errors for failed calls can be checked using errno */

/*!
 * \brief Create a new TCP session
 * \param fd File descriptor
 * \param unbuffered Whether to disable Nagle's algorithm (1 if the application provides its own buffering)
 */
struct tcp_session *tcp_create(int fd, int unbuffered);

/*! \brief Enable logging to file for TCP session */
int tcp_open_log(struct tcp_session *tcp, const char *logfile);

/*! \brief Get the session, if there is one, for a file descriptor */
struct tcp_session *tcp_session_get(int fd);

/*! \brief Close TCP session, closing the file descriptor passed into tcp_create. Optional (although tcp_destroy must still be called) */
int tcp_close(struct tcp_session *tcp);

/*! \brief Destroy and free TCP session */
void tcp_destroy(struct tcp_session *tcp);

/* \brief I/O function replacements */

/*! \brief Poll a TCP session for POLLOUT */
ssize_t tcp_poll(struct tcp_session *tcp, int ms);

/*! \brief Read from TCP session */
ssize_t tcp_read(struct tcp_session *tcp, char *buf, size_t len);

/*! \brief Wrapper for write() */
ssize_t tcp_write(struct tcp_session *tcp, const char *buf, size_t len);

/*! \brief Wrapper for sendfile() */
ssize_t tcp_sendfile(struct tcp_session *tcp, int in_fd, off_t *offset, size_t count);

/* \brief Abstracted I/O functions */

/*! \brief Drop-in replacement for write() (use ABSTRACT_TCP_IO) */
ssize_t tcp_abstract_write(int fd, const char *buf, size_t len);

#ifdef ABSTRACT_TCP_IO
#include <unistd.h>
#undef write
#define write(fd, buf, len) tcp_abstract_write(fd, buf, len)
#endif

/* Stat functions */

/*! \brief Whether the estimated speed has converged yet. If not, more data transfer is needed or the previous data transfer was not sufficiently long enough. */
int tcp_speed_converged(struct tcp_session *tcp);

/*! \brief Whether the estimated speed is above the broadband threshold */
int tcp_speed_is_broadband(struct tcp_session *tcp);

/*! \brief Get the estimated speed, in bits per second (only usable once tcp_speed_converged returns true) */
double tcp_speed(struct tcp_session *tcp);

/*! \brief Get number of bytes sent during entire session */
size_t tcp_bytes_sent(struct tcp_session *tcp);
