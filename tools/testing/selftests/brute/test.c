// SPDX-License-Identifier: GPL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *message = "message";

enum mode {
	MODE_NONE,
	MODE_CRASH,
	MODE_SERVER_CRASH,
	MODE_CLIENT,
};

enum crash_after {
	CRASH_AFTER_NONE,
	CRASH_AFTER_FORK,
	CRASH_AFTER_EXEC,
};

enum signal_from {
	SIGNAL_FROM_NONE,
	SIGNAL_FROM_USER,
	SIGNAL_FROM_KERNEL,
};

struct args {
	uint32_t ip;
	uint16_t port;
	int counter;
	long timeout;
	enum mode mode;
	enum crash_after crash_after;
	enum signal_from signal_from;
	unsigned char has_counter : 1;
	unsigned char has_change_priv : 1;
	unsigned char has_ip : 1;
	unsigned char has_port : 1;
	unsigned char has_timeout : 1;
};

#define OPT_STRING "hm:c:s:n:Ca:p:t:"

static void usage(const char *prog)
{
	printf("Usage: %s <OPTIONS>\n", prog);
	printf("OPTIONS:\n");
	printf("  -h: Show this help and exit. Optional.\n");
	printf("  -m (crash | server_crash | client): Mode. Required.\n");
	printf("Options for crash mode:\n");
	printf("  -c (fork | exec): Crash after. Optional.\n");
	printf("  -s (user | kernel): Signal from. Required.\n");
	printf("  -n counter: Number of crashes.\n");
	printf("              Required if the option -c is used.\n");
	printf("              Not used without the option -c.\n");
	printf("              Range from 1 to INT_MAX.\n");
	printf("  -C: Change privileges before crash. Optional.\n");
	printf("Options for server_crash mode:\n");
	printf("  -a ip: Ip v4 address to accept. Required.\n");
	printf("  -p port: Port number. Required.\n");
	printf("           Range from 1 to UINT16_MAX.\n");
	printf("  -t secs: Accept timeout. Required.\n");
	printf("           Range from 1 to LONG_MAX.\n");
	printf("  -c (fork | exec): Crash after. Required.\n");
	printf("  -s (user | kernel): Signal from. Required.\n");
	printf("  -n counter: Number of crashes. Required.\n");
	printf("              Range from 1 to INT_MAX.\n");
	printf("Options for client mode:\n");
	printf("  -a ip: Ip v4 address to connect. Required.\n");
	printf("  -p port: Port number. Required.\n");
	printf("           Range from 1 to UINT16_MAX.\n");
	printf("  -t secs: Connect timeout. Required.\n");
	printf("           Range from 1 to LONG_MAX.\n");
}

static __attribute__((noreturn)) void info_failure(const char *message,
						   const char *prog)
{
	printf("%s\n", message);
	usage(prog);
	exit(EXIT_FAILURE);
}

static enum mode get_mode(const char *text, const char *prog)
{
	if (!strcmp(text, "crash"))
		return MODE_CRASH;

	if (!strcmp(text, "server_crash"))
		return MODE_SERVER_CRASH;

	if (!strcmp(text, "client"))
		return MODE_CLIENT;

	info_failure("Invalid mode option [-m].", prog);
}

static enum crash_after get_crash_after(const char *text, const char *prog)
{
	if (!strcmp(text, "fork"))
		return CRASH_AFTER_FORK;

	if (!strcmp(text, "exec"))
		return CRASH_AFTER_EXEC;

	info_failure("Invalid crash after option [-c].", prog);
}

static enum signal_from get_signal_from(const char *text, const char *prog)
{
	if (!strcmp(text, "user"))
		return SIGNAL_FROM_USER;

	if (!strcmp(text, "kernel"))
		return SIGNAL_FROM_KERNEL;

	info_failure("Invalid signal from option [-s]", prog);
}

static int get_counter(const char *text, const char *prog)
{
	int counter;

	counter = atoi(text);
	if (counter > 0)
		return counter;

	info_failure("Invalid counter option [-n].", prog);
}

static __attribute__((noreturn)) void error_failure(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static uint32_t get_ip(const char *text, const char *prog)
{
	int ret;
	uint32_t ip;

	ret = inet_pton(AF_INET, text, &ip);
	if (!ret)
		info_failure("Invalid ip option [-a].", prog);
	else if (ret < 0)
		error_failure("inet_pton");

	return ip;
}

static uint16_t get_port(const char *text, const char *prog)
{
	long port;

	port = atol(text);
	if ((port > 0) && (port <= UINT16_MAX))
		return htons(port);

	info_failure("Invalid port option [-p].", prog);
}

static long get_timeout(const char *text, const char *prog)
{
	long timeout;

	timeout = atol(text);
	if (timeout > 0)
		return timeout;

	info_failure("Invalid timeout option [-t].", prog);
}

static void check_args(const struct args *args, const char *prog)
{
	if (args->mode == MODE_CRASH && args->crash_after != CRASH_AFTER_NONE &&
	    args->signal_from != SIGNAL_FROM_NONE && args->has_counter &&
	    !args->has_ip && !args->has_port && !args->has_timeout)
		return;

	if (args->mode == MODE_CRASH && args->signal_from != SIGNAL_FROM_NONE &&
	    args->crash_after == CRASH_AFTER_NONE && !args->has_counter &&
	    !args->has_ip && !args->has_port && !args->has_timeout)
		return;

	if (args->mode == MODE_SERVER_CRASH && args->has_ip && args->has_port &&
	    args->has_timeout && args->crash_after != CRASH_AFTER_NONE &&
	    args->signal_from != SIGNAL_FROM_NONE && args->has_counter &&
	    !args->has_change_priv)
		return;

	if (args->mode == MODE_CLIENT && args->has_ip && args->has_port &&
	    args->has_timeout && args->crash_after == CRASH_AFTER_NONE &&
	    args->signal_from == SIGNAL_FROM_NONE && !args->has_counter &&
	    !args->has_change_priv)
		return;

	info_failure("Invalid use of options.", prog);
}

static uid_t get_non_root_uid(void)
{
	struct passwd *pwent;
	uid_t uid;

	while (true) {
		errno = 0;
		pwent = getpwent();
		if (!pwent) {
			if (errno) {
				perror("getpwent");
				endpwent();
				exit(EXIT_FAILURE);
			}
			break;
		}

		if (pwent->pw_uid) {
			uid = pwent->pw_uid;
			endpwent();
			return uid;
		}
	}

	endpwent();
	printf("A user different of root is needed.\n");
	exit(EXIT_FAILURE);
}

static inline void do_sigsegv(void)
{
	int *p = NULL;
	*p = 0;
}

static void do_sigkill(void)
{
	int ret;

	ret = kill(getpid(), SIGKILL);
	if (ret)
		error_failure("kill");
}

static void crash(enum signal_from signal_from, bool change_priv)
{
	int ret;

	if (change_priv) {
		ret = setuid(get_non_root_uid());
		if (ret)
			error_failure("setuid");
	}

	if (signal_from == SIGNAL_FROM_KERNEL)
		do_sigsegv();

	do_sigkill();
}

static void execve_crash(char *const argv[])
{
	execve(argv[0], argv, NULL);
	error_failure("execve");
}

static void exec_crash_user(void)
{
	char *const argv[] = {
		"./test", "-m", "crash", "-s", "user", NULL,
	};

	execve_crash(argv);
}

static void exec_crash_user_change_priv(void)
{
	char *const argv[] = {
		"./test", "-m", "crash", "-s", "user", "-C", NULL,
	};

	execve_crash(argv);
}

static void exec_crash_kernel(void)
{
	char *const argv[] = {
		"./test", "-m", "crash", "-s", "kernel", NULL,
	};

	execve_crash(argv);
}

static void exec_crash_kernel_change_priv(void)
{
	char *const argv[] = {
		"./test", "-m", "crash", "-s", "kernel", "-C", NULL,
	};

	execve_crash(argv);
}

static void exec_crash(enum signal_from signal_from, bool change_priv)
{
	if (signal_from == SIGNAL_FROM_USER && !change_priv)
		exec_crash_user();
	if (signal_from == SIGNAL_FROM_USER && change_priv)
		exec_crash_user_change_priv();
	if (signal_from == SIGNAL_FROM_KERNEL && !change_priv)
		exec_crash_kernel();
	if (signal_from == SIGNAL_FROM_KERNEL && change_priv)
		exec_crash_kernel_change_priv();
}

static void do_crash(enum crash_after crash_after, enum signal_from signal_from,
		     int counter, bool change_priv)
{
	pid_t pid;
	int status;

	if (crash_after == CRASH_AFTER_NONE)
		crash(signal_from, change_priv);

	while (counter > 0) {
		pid = fork();
		if (pid < 0)
			error_failure("fork");

		/* Child process */
		if (!pid) {
			if (crash_after == CRASH_AFTER_FORK)
				crash(signal_from, change_priv);

			exec_crash(signal_from, change_priv);
		}

		/* Parent process */
		counter -= 1;
		pid = waitpid(pid, &status, 0);
		if (pid < 0)
			error_failure("waitpid");
	}
}

static __attribute__((noreturn)) void error_close_failure(const char *message,
							  int fd)
{
	perror(message);
	close(fd);
	exit(EXIT_FAILURE);
}

static void do_server(uint32_t ip, uint16_t port, long accept_timeout)
{
	int sockfd;
	int ret;
	struct sockaddr_in address;
	struct timeval timeout;
	int newsockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error_failure("socket");

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = ip;
	address.sin_port = port;

	ret = bind(sockfd, (const struct sockaddr *)&address, sizeof(address));
	if (ret)
		error_close_failure("bind", sockfd);

	ret = listen(sockfd, 1);
	if (ret)
		error_close_failure("listen", sockfd);

	timeout.tv_sec = accept_timeout;
	timeout.tv_usec = 0;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
			 (const struct timeval *)&timeout, sizeof(timeout));
	if (ret)
		error_close_failure("setsockopt", sockfd);

	newsockfd = accept(sockfd, NULL, NULL);
	if (newsockfd < 0)
		error_close_failure("accept", sockfd);

	close(sockfd);
	close(newsockfd);
}

static void do_client(uint32_t ip, uint16_t port, long connect_timeout)
{
	int sockfd;
	int ret;
	struct timeval timeout;
	struct sockaddr_in address;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error_failure("socket");

	timeout.tv_sec = connect_timeout;
	timeout.tv_usec = 0;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO,
			 (const struct timeval *)&timeout, sizeof(timeout));
	if (ret)
		error_close_failure("setsockopt", sockfd);

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = ip;
	address.sin_port = port;

	ret = connect(sockfd, (const struct sockaddr *)&address,
		      sizeof(address));
	if (ret)
		error_close_failure("connect", sockfd);

	ret = write(sockfd, message, strlen(message));
	if (ret < 0)
		error_close_failure("write", sockfd);

	close(sockfd);
}

#define PROG_NAME basename(argv[0])

int main(int argc, char **argv)
{
	int opt;
	struct args args = {
		.mode = MODE_NONE,
		.crash_after = CRASH_AFTER_NONE,
		.signal_from = SIGNAL_FROM_NONE,
		.has_counter = false,
		.has_change_priv = false,
		.has_ip = false,
		.has_port = false,
		.has_timeout = false,
	};

	while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
		switch (opt) {
		case 'h':
			usage(PROG_NAME);
			return EXIT_SUCCESS;
		case 'm':
			args.mode = get_mode(optarg, PROG_NAME);
			break;
		case 'c':
			args.crash_after = get_crash_after(optarg, PROG_NAME);
			break;
		case 's':
			args.signal_from = get_signal_from(optarg, PROG_NAME);
			break;
		case 'n':
			args.counter = get_counter(optarg, PROG_NAME);
			args.has_counter = true;
			break;
		case 'C':
			args.has_change_priv = true;
			break;
		case 'a':
			args.ip = get_ip(optarg, PROG_NAME);
			args.has_ip = true;
			break;
		case 'p':
			args.port = get_port(optarg, PROG_NAME);
			args.has_port = true;
			break;
		case 't':
			args.timeout = get_timeout(optarg, PROG_NAME);
			args.has_timeout = true;
			break;
		default:
			usage(PROG_NAME);
			return EXIT_FAILURE;
		}
	}

	check_args(&args, PROG_NAME);

	if (args.mode == MODE_CRASH) {
		do_crash(args.crash_after, args.signal_from, args.counter,
			 args.has_change_priv);
	} else if (args.mode == MODE_SERVER_CRASH) {
		do_server(args.ip, args.port, args.timeout);
		do_crash(args.crash_after, args.signal_from, args.counter,
			 false);
	} else if (args.mode == MODE_CLIENT) {
		do_client(args.ip, args.port, args.timeout);
	}

	return EXIT_SUCCESS;
}
