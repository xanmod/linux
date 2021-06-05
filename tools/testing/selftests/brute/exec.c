// SPDX-License-Identifier: GPL-2.0

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static __attribute__((noreturn)) void error_failure(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

#define PROG_NAME basename(argv[0])
#define CLD_BRUTE	7	/* child was killed by brute LSM */

int main(int argc, char **argv)
{
	pid_t pid;
	int rc;
	siginfo_t siginfo;

	if (argc < 2) {
		printf("Usage: %s <EXECUTABLE>\n", PROG_NAME);
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid < 0)
		error_failure("fork");

	/* Child process */
	if (!pid) {
		execve(argv[1], &argv[1], NULL);
		error_failure("execve");
	}

	/* Parent process */
	rc = waitid(P_PID, pid, &siginfo, WEXITED);
	if (rc)
		error_failure("waitid");

	return siginfo.si_code != CLD_BRUTE;
}
