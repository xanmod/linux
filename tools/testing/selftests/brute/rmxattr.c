// SPDX-License-Identifier: GPL-2.0

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/xattr.h>

static __attribute__((noreturn)) void error_failure(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

#define PROG_NAME basename(argv[0])

#define XATTR_SECURITY_PREFIX "security."
#define XATTR_BRUTE_SUFFIX "brute"
#define XATTR_NAME_BRUTE XATTR_SECURITY_PREFIX XATTR_BRUTE_SUFFIX

int main(int argc, char **argv)
{
	int rc;

	if (argc < 2) {
		printf("Usage: %s <FILE>\n", PROG_NAME);
		exit(EXIT_FAILURE);
	}

	rc = removexattr(argv[1], XATTR_NAME_BRUTE);
	if (rc)
		error_failure("removexattr");

	return EXIT_SUCCESS;
}
