#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "seccomp-bpf.h"


static void drop_privileges(void)
{
	struct passwd *user;
	struct rlimit limit;

	if (!geteuid()) {
		user = getpwnam("nobody");
		if (!user) {
			perror("getpwnam");
			exit(EXIT_FAILURE);
		}
		if (chroot("/var/empty")) {
			perror("chroot");
			exit(EXIT_FAILURE);
		}
		if (chdir("/")) {
			perror("chdir");
			exit(EXIT_FAILURE);
		}
		if (setresgid(user->pw_gid, user->pw_gid, user->pw_gid)) {
			perror("setresgid");
			exit(EXIT_FAILURE);
		}
		if (setgroups(1, &user->pw_gid)) {
			perror("setgroups");
			exit(EXIT_FAILURE);
		}
		if (setresuid(user->pw_uid, user->pw_uid, user->pw_uid)) {
			perror("setresuid");
			exit(EXIT_FAILURE);
		}
	}
	limit.rlim_cur = limit.rlim_max = 4194304 /* 4 megs */;
	setrlimit(RLIMIT_DATA, &limit);
	setrlimit(RLIMIT_FSIZE, &limit);
	setrlimit(RLIMIT_MEMLOCK, &limit);
	setrlimit(RLIMIT_STACK, &limit);
	limit.rlim_cur = limit.rlim_max = 15728640 /* 15 megabytes */;
	setrlimit(RLIMIT_AS, &limit);
	limit.rlim_cur = limit.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &limit);
	setrlimit(RLIMIT_NPROC, &limit);

	if (!geteuid() || !getegid()) {
		fprintf(stderr, "Error: unable to drop privileges.\n");
		exit(EXIT_FAILURE);
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(EXIT_FAILURE);
	}

	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) {
		perror("prctl(PR_SET_DUMPABLE)");
		exit(EXIT_FAILURE);
	}
}

static void seccomp_enable_filter(void)
{
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL,
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(epoll_wait),
		ALLOW_SYSCALL(epoll_ctl),
		ALLOW_SYSCALL(accept4),
		ALLOW_SYSCALL(close),
		ALLOW_SYSCALL(mmap),
		ALLOW_SYSCALL(fstat),
		ALLOW_SYSCALL(newfstatat),
		KILL_PROCESS
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter
	};
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		exit(EXIT_FAILURE);
	}
}


int main(int argc, char *argv[]) {
	seccomp_enable_filter();
	printf("%d\n", argc);
	for (int i=argc-1; i>=0; i--)
		printf("%s\n", argv[i]);
}
