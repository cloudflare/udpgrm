#define _GNU_SOURCE // clone
#include <errno.h>
#include <error.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <syscall.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

static sigset_t default_sigmask;
/* Set in clone_child only, contains child's own pid */
static pid_t child_tid;

#define PID_ENV "LISTEN_PID"

struct execve_params {
	char *pathname;
	char **argv;
	char **envp;
};

static int clone_child(void *arg)
{
	/* copy to local stack */
	struct execve_params e = *(struct execve_params *)arg;
	char listen_pid_var[32];

	sigprocmask(SIG_SETMASK, &default_sigmask, NULL);

	/* if systemd provides notify socket, fix LISTEN_PID for child */
	for (char **env = e.envp; *env != NULL; env++) {
		if (strncmp(PID_ENV, *env, strlen(PID_ENV)) == 0) {
			snprintf(&listen_pid_var[0], sizeof(listen_pid_var),
				 PID_ENV "=%" PRIu32, child_tid);
			*env = &listen_pid_var[0];
			break;
		}
	}

	execve(e.pathname, e.argv, e.envp);
	/* execve() should never exit */
	error(-1, errno, "execve(%s)", e.pathname);
	abort();
}

static pid_t fork_execve_pidfd(int *child_pidfd, char **argv, char **envp)
{
	char stack[1024];
	char *stack_top = stack + sizeof(stack);

	struct execve_params e = {.pathname = argv[0], .argv = argv, .envp = envp};

	int pidfd = -1;
	int pid = clone(clone_child, stack_top - ((long)stack_top & 0xf),
			CLONE_PIDFD | CLONE_CHILD_SETTID | SIGCHLD, &e, &pidfd, NULL,
			&child_tid);
	if (pid <= 0) {
		return pid;
	}

	if (child_pidfd) {
		*child_pidfd = pidfd;
	} else {
		close(pidfd);
	}
	return pid;
}

static int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
	return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

int main(int argc, char **argv, char **envp)
{
	(void)argc;
	sigset_t mask;

	/* All signals */
	sigfillset(&mask);

	int sfd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (sfd == -1) {
		error(-1, errno, "signalfd()");
	}

	/* Block signals so that they aren't handled
	   according to their default dispositions */
	if (sigprocmask(SIG_BLOCK, &mask, &default_sigmask) == -1) {
		error(-1, errno, "sigprocmask()");
	}

	char **child_argv = &argv[1];

	if (*child_argv == NULL) {
		error(-1, 0, "Usage: %s -- COMMAND [ARGS]", argv[0]);
	}

	if (strcmp(child_argv[0], "--") == 0) {
		child_argv = &argv[2];
	}

	int child_pidfd = -1;
	pid_t child_pid = fork_execve_pidfd(&child_pidfd, child_argv, envp);
	if (child_pid < 1) {
		error(-1, errno, "clone3()");
	}

	while (1) {
		struct signalfd_siginfo fdsi;
		ssize_t s = read(sfd, &fdsi, sizeof(fdsi));
		if (s != sizeof(fdsi))
			error(-1, EMSGSIZE, "read(signalfd)");

		if (fdsi.ssi_pid == (uint32_t)child_pid && fdsi.ssi_signo == SIGCHLD) {
			/* Child had died. Copy its status. */
			exit(fdsi.ssi_status);
		}

		if (fdsi.ssi_pid == (uint32_t)child_pid && fdsi.ssi_signo == SIGURG) {
			/* SIGURG from child means we should exit,
			   it entered graceful shutdown mode */
			exit(0);
		}

		/* Signals from parent always forward */
		int r = pidfd_send_signal(child_pidfd, fdsi.ssi_signo, NULL, 0);
		if (r != 0) {
			/* If signal send fails, just ignore and wait for SIGCHLD. */
		}
	}
}
