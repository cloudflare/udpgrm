// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <systemd/sd-daemon.h>
#include <time.h>
#include <unistd.h>

#include "../ebpf.skel.h"
#include "common.h"

#if (LIBBPF_MAJOR_VERSION < 1) || (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION < 3)
#error "libbpf version 1.3 or higher is required."
#endif

struct ebpf *skel;

/* long options */
static int without_sendmsg = 0;

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static void usage()
{
	printf(
#include "usage.txt"
	);
}

static int libbpf_no_print(enum libbpf_print_level level, const char *a, va_list ap)
{
	(void)level;
	(void)a;
	(void)ap;
	return 0;
}

static int libbpf_base_print(enum libbpf_print_level level, const char *format,
			     va_list args)
{
	if (level == LIBBPF_DEBUG) {
		return 0;
	}
	return vfprintf(stderr, format, args);
}

static char *skey_sprint(const struct reuseport_storage_key *skey)
{
	static char buf[64];
	memset(buf, 0, sizeof(buf));

	if (skey->family == AF_INET) {
		uint8_t *ip = (uint8_t *)&skey->src_ip4;
		snprintf(buf, 64, "udp://%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3],
			 skey->src_port);
	} else if (skey->family == AF_INET6) {
		uint16_t ip[8];
		memcpy(ip, &skey->src_ip6, 16);
		snprintf(buf, 64, "udp://[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%d",
			 ntohs(ip[0]), ntohs(ip[1]), ntohs(ip[2]), ntohs(ip[3]),
			 ntohs(ip[4]), ntohs(ip[5]), ntohs(ip[6]), ntohs(ip[7]),
			 skey->src_port);
	} else {
		snprintf(buf, 64, "unknown-%d://", skey->family);
	}
	return buf;
}

struct handle_msg_ctx {
	char *tubular_path;
};

static void sockaddr_from_msg_value(struct sockaddr_storage *ss, struct msg_value *e)
{
	memset(ss, 0, sizeof(*ss));
	ss->ss_family = AF_UNSPEC;

	switch (e->skey.family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(e->skey.src_port);
		sin->sin_addr.s_addr = e->skey.src_ip4;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(e->skey.src_port);
		memcpy(&sin6->sin6_addr, e->skey.src_ip6, 16);
		break;
	}
	}
}


static int handle_msg(void *_ctx, void *data, size_t data_sz)
{
	struct handle_msg_ctx *ctx = _ctx;
	struct msg_value ee = {};
	struct msg_value *e = &ee;
	memcpy(e, data, data_sz);

	struct reuseport_storage state = {};
	int r = bpf_map_lookup_elem(bpf_map__fd(skel->maps.reuseport_storage_map),
				    &e->skey, &state);
	if (r != 0 && e->type != MSG_LOG) {
		error(-1, errno,
		      "bpf_map_lookup_elem(): empty reuseport_storage_map state for %s "
		      "r=%d msg_type=%d. Perhaps ring overrun.",
		      skey_sprint(&e->skey), r, e->type);
	}

	if (e->type == MSG_LOG) {
		if (e->skey.family != 0) {
			printf("%s %.*s", skey_sprint(&e->skey), (int)sizeof(e->log), (char *)&e->log);
		} else {
			printf("%.*s", (int)sizeof(e->log), (char *)&e->log);
		}
	}

	if (e->type == MSG_REGISTER_SOCKET) {
		/* printf("[+] Fishing up pid=%d for socket. Cookie=0x%lx\n", e->pid, */
		/*        e->cookie); */
		int pidfd = pidfd_open(e->pid, 0);
		if (pidfd < 0) {
			printf("%s [!] Pid %d requested MSG_REGISTER_SOCKET, but have "
			       "died since, ignoring\n",
			       skey_sprint(&e->skey), e->pid);
			goto err;
		}

		struct sockaddr_storage addr;
		sockaddr_from_msg_value(&addr, e);

		int f = pidfd_find_socket(pidfd, 8, SOCK_DGRAM, IPPROTO_UDP, &addr,
					  e->socket_cookie);

		if (f >= 0) {
			uint64_t fd_v = f;
			int close_fd = 1;
			int free_pos;
			int gen_len = 0;
			struct socket_storage s;
			r = bpf_map_lookup_elem(bpf_map__fd(skel->maps.sk_storage_map),
						&f, &s);
			if (r != 0) {
				error(-1, -1, "bpf_sk_storage_get");
			}

			uint32_t gen = TO_WRK_GEN(state.dis.max_apps, e->socket_app,
						  e->socket_gen);

			{
				int sockhash_fd = bpf_map__fd(skel->maps.sockhash);

				int prev_pos;
				cookies_find_empty(&state, gen, sockhash_fd,
						   e->socket_cookie, &prev_pos, &free_pos,
						   &gen_len);

				if (free_pos < 0 || free_pos >= MAX_SOCKETS_IN_GEN) {
					printf("[!] too many sockets in the gen!\n");
					free_pos = -1;
				} else {
					r = bpf_map_update_elem(sockhash_fd,
								&e->socket_cookie, &fd_v,
								BPF_NOEXIST);
					if (r != 0) {
						if (errno == EEXIST) {
							printf("[D] registering socket "
							       "again is legal but "
							       "weird\n");
						} else {
							error(-1, errno,
							      "bpf_map_update_elem("
							      "sockhash)");
						}
					}
				}
			}

			if (free_pos >= 0) {
				close_fd = tubular_maybe_preserve_fd(&state, gen, gen_len,
								     free_pos, f);

				{
					struct msg_value msg;
					memset(&msg, 0, sizeof(msg));
					msg = (struct msg_value){
						.skey = e->skey,
						.type = GSM_SET_COOKIES,
						.sock_gen = gen,
						.sock_idx = free_pos,
						.sock_gen_len = gen_len,
						.sock_cookie = e->socket_cookie,
					};
					run_cb_update_map(&msg);
				}

				uint32_t v;
				grm_cookie_pack(e->socket_gen, free_pos, (uint8_t *)&v);
				printf("%s [D] socket found so_cookie=0x%lx app=%d "
				       "gen=%d/%d/%d idx=%d udpgrm_cookie=0x%04x\n",
				       skey_sprint(&e->skey), s.so_cookie, s.sock_app,
				       s.sock_gen, e->socket_gen, gen, free_pos, v);
				s.sock_idx = free_pos;
				r = bpf_map_update_elem(
					bpf_map__fd(skel->maps.sk_storage_map), &f, &s,
					BPF_EXIST);
				if (r != 0) {
					// We have reference to socket, so it's not dead
					error(-1, -1, "Failed to update sk_storage");
				}
			}

			int prog_fd = bpf_program__fd(skel->progs.udpgrm_reuseport_prog);

			if (prog_fd < 0) {
				error(-1, errno, "bpf_program__fd()");
			}

			r = setsockopt(f, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd,
				       sizeof(prog_fd));
			if (r != 0) {
				error(-1, errno, "setsockopt(SO_ATTACH_REUSEPORT_EBPF)");
			}

			if (close_fd) {
				close(f);
			}
		} else {
			printf("%s [D] Socket not found. Pretty bad\n",
			       skey_sprint(&e->skey));
			metric_incr_critical(&e->skey, 1, 1);
		}
	err:;
		if (pidfd >= 0)
			close(pidfd);
	}

	if (e->type == MSG_SET_WORKING_GEN) {
		printf("%s [D] Working gen app=%d %d curr=%d  %s label=%.*s\n",
		       skey_sprint(&e->skey), e->app_idx, e->app_working_gen,
		       state.working_gen[e->app_idx % MAX_APPS], ctx->tubular_path,
		       LABEL_SZ, state.dis.label);

		int wg = e->app_working_gen % MAX_GENS;

		int err = tubular_maybe_register(&state, wg, ctx->tubular_path);
		if (err) {
			printf("%s [D] Tubular register failed: %s\n",
			       skey_sprint(&e->skey), strerror(err));
			metric_incr_critical(&e->skey, 1, 1);
		} else {
			metric_incr_critical(&e->skey, 0, 0);
		}
	}

	return 0;
}

static struct ring_buffer *rb_setup_msg(char *tubular_path)
{
	int map_fd = bpf_map__fd(skel->maps.msg_rb);
	if (map_fd < 0) {
		error(-1, errno, "bpf_map__fd");
	}

	struct handle_msg_ctx *ctx = calloc(1, sizeof(struct handle_msg_ctx));
	ctx->tubular_path = tubular_path;
	struct ring_buffer *rb = ring_buffer__new(map_fd, handle_msg, ctx, NULL);
	if (!rb) {
		error(-1, errno, "Failed to create ring buffer\n");
	}

	uint32_t info_sz = sizeof(struct bpf_map_info);
	struct bpf_map_info info = {};
	int r = bpf_obj_get_info_by_fd(map_fd, &info, &info_sz);
	if (r != 0) {
		error(-1, errno, "bpf_obj_get_info_by_fd()");
	}

	fprintf(stderr, "[*] Tailing message ring buffer  map_id %d\n", info.id);
	return rb;
}

enum {
	CMD_NONE = 0,
	CMD_LIST = 1,
	CMD_FLOWS = 2,
	CMD_DELETE = 3,
	CMD_METRICS = 4,
};

int main(int argc, char *argv[])
{

	char *cgroup_paths[] = {"/sys/fs/cgroup/unified", "/sys/fs/cgroup", NULL};

	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"pin-dir", required_argument, 0, 'p'},
		{"install", optional_argument, 0, 'i'},
		{"tubular", required_argument, 0, 't'},
		{"daemon", no_argument, 0, 'd'},
		{"verbose", no_argument, 0, 'v'},
		{"self", no_argument, 0, 's'},
		{"force", no_argument, 0, 'f'},
		{"without-sendmsg", no_argument, &without_sendmsg, 1},
		{NULL, 0, 0, 0}};

	const char *optstring = optstring_from_long_options(long_options);
	char *bpf_pin_dir = "/sys/fs/bpf/udpgrm";
	int do_install = 0, do_daemon = 0;
	int cgroup_self = 0;
	int verbose = 0;
	char *tubular_path = NULL;
	int retcode = 0;
	int force = 0;

	optind = 1;
	while (1) {
		int arg = getopt_long(argc, argv, optstring, long_options, NULL);
		if (arg == -1) {
			break;
		}

		switch (arg) {
		case 0:
			/* Long option */
			break;

		default:
		case '?':
			exit(-1);
			break;

		case 'h':
			usage();
			exit(-2);
			break;

		case 'i':
			/* Install bpf hooks in given cgroup. */
			if (optarg != NULL) {
				cgroup_paths[0] = optarg;
				cgroup_paths[1] = NULL;
			}
			do_install++;
			break;

		case 't':
			tubular_path = optarg;
			break;

		case 'p':
			/* udpgrm owns this directory and removes it all files at exit
			 */
			bpf_pin_dir = optarg;
			break;

		case 'v':
			verbose++;
			break;

		case 'd':
			/* Create bpf programs and pin them to bpffs. */
			do_daemon++;
			break;

		case 's':
			cgroup_self = 1;
			break;

		case 'f':
			force++;
			break;
		}
	}

	char *reuseport_name = NULL;
	int do_command = CMD_NONE;
	if (argv[optind] && strcmp(argv[optind], "list") == 0) {
		do_command = CMD_LIST;
		reuseport_name = argv[optind + 1];
	}

	if (argv[optind] &&
	    (strcmp(argv[optind], "flow") == 0 || strcmp(argv[optind], "flows") == 0)) {
		do_command = CMD_FLOWS;
		reuseport_name = argv[optind + 1];
	}

	if (argv[optind] && (strcmp(argv[optind], "delete") == 0)) {
		do_command = CMD_DELETE;
		reuseport_name = argv[optind + 1];
	}

	if (argv[optind] && strcmp(argv[optind], "metrics") == 0) {
		do_command = CMD_METRICS;
		reuseport_name = argv[optind + 1];
	}

	if (do_command == CMD_NONE && argv[optind]) {
		error(-1, 0, "Not sure what you mean by %s", argv[optind]);
	}

	if ((do_daemon || do_install) && do_command != CMD_NONE) {
		error(-1, 0, "Invalid combination of arguments");
	}

	if (do_daemon == 0 && do_install == 0 && do_command == CMD_NONE) {
		error(-1, 0,
		      "You probably want either --daemon or "
		      "--install=/sys/fs/cgroup/system.slice/... or  both. Or "
		      "instruction like [list|flow].");
	}

	if (tubular_path != 0 && do_daemon == 0) {
		error(-1, 0, "You don't need --tubular without --daemon");
	}

	struct sockaddr_storage reuseport_ss = {};
	if (reuseport_name != NULL) {
		int r = net_parse_sockaddr(&reuseport_ss, reuseport_name, 0);
		if (r < 0)
			error(-1, 0, "Can't parse %s", reuseport_name);
		if (net_get_port(&reuseport_ss) == 0)
			error(-1, 0, "Can't parse %s", reuseport_name);
	}

	int prog_fd, map_fd;
	if (do_command != CMD_NONE) {
		char b[PATH_MAX];
		snprintf(b, sizeof(b), "%s/%s", bpf_pin_dir, "setsockopt");
		prog_fd = bpf_obj_get(b);
		if (prog_fd < 0)
			error(-1, errno,
			      "bpf_obj_get(%s): Are udpgrm cgroup hooks loaded? ", b);

		fprintf(stderr, "[ ] Retrievieng BPF progs from %s\n", bpf_pin_dir);
	}

	if (do_command != CMD_NONE) {
		map_fd = map_from_prog(prog_fd, "reuseport_stora", NULL);
		if (map_fd < 0)
			error(-1, errno, "map_from_prog()");
	}

	if (do_command == CMD_LIST) {
		do_list(prog_fd, map_fd, &reuseport_ss, verbose);
		return 0;
	}

	if (do_command == CMD_FLOWS) {
		do_flows(prog_fd, map_fd, &reuseport_ss, verbose);
		return 0;
	}

	if (do_command == CMD_DELETE) {
		// Perhaps we might validate if all sockets are dead,
		// otherwise we still might have reuseport group EBPF
		// loaded, which will fall back to default reuseport
		// group semantics at a lack of map entry.
		struct reuseport_storage_key key = {};
		skey_from_ss(&key, &reuseport_ss);
		struct reuseport_storage s = {};
		int r = bpf_map_lookup_elem(map_fd, &key, &s);
		if (r != 0)
			error(-1, 0, "Can't find reuseport group %s", reuseport_name);

		r = bpf_map_delete_elem(map_fd, &key);
		if (r != 0)
			error(-1, 0, "Failed to delete reuseport group %s",
			      reuseport_name);
	}

	if (do_command == CMD_METRICS) {
		do_metrics(prog_fd, map_fd);
		return 0;
	}

	if (do_daemon != 0) {
		/* First load bpf. This should be done before mkdir,
		 * so that if verifier fails, we don't create the
		 * dir.  */
		fprintf(stderr, "[ ] Loading BPF code\n");

		bump_memlock_rlimit();
		/* Silence stupid libbpf. */
		libbpf_set_print(libbpf_no_print);

		skel = ebpf__open_and_load();
		if (skel == NULL) {
			libbpf_set_print(libbpf_base_print);
			skel = ebpf__open_and_load();
			if (skel == NULL)
				error(-1, errno,
				      "ebpf__open() failed. Perhaps linked libbpf.so "
				      "version is too "
				      "old");
		}

		/* If creating the hooks, allow for auto-mkdir semantics. */
		struct stat sb;
		if (stat(bpf_pin_dir, &sb) == 0) {
			if (force == 0) {
				error(-1, EEXIST,
				      "[!] Looks like %s BPF fs path exists. If you "
				      "think udpgrm daemon crashed, remove it before "
				      "continuing. Or rerun with --force.",
				      bpf_pin_dir);
			} else {
				fprintf(stderr,
					"[!] Looks like %s BPF fs path exists and "
					"--force given. Removing it.\n",
					bpf_pin_dir);
			}
			cleanup_bpf_pin_dir(bpf_pin_dir);

			if (stat(bpf_pin_dir, &sb) == 0) {
				error(-1, EEXIST, "BPF cleanup failed, aborting");
			}
		}
		int r = mkdir(bpf_pin_dir, 0777);
		if (r != 0)
			error(-1, errno, "mkdir(%s)", bpf_pin_dir);
		if (stat(bpf_pin_dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
			error(-1, EEXIST, "Does %s bpf fs directory exist?", bpf_pin_dir);
		}

		fprintf(stderr, "[ ] Pinning bpf programs to %s\n", bpf_pin_dir);
		int do_reload = 1;
#define PIN(fd, dir, suffix, do_unlink)                                                  \
	{                                                                                \
		char b[PATH_MAX];                                                        \
		snprintf(b, sizeof(b), "%s/%s", dir, suffix);                            \
		int r = bpf_obj_pin(fd, b);                                              \
		if (do_unlink && errno == EEXIST) {                                      \
			unlink(b);                                                       \
			r = bpf_obj_pin(fd, b);                                          \
		}                                                                        \
		if (r != 0)                                                              \
			error(-1, errno, "bpf_obj_pin(" suffix ")");                     \
	}

		init_metrics(bpf_program__fd(skel->progs.udpgrm_setsockopt));

		PIN(bpf_program__fd(skel->progs.udpgrm_setsockopt), bpf_pin_dir,
		    "setsockopt", do_reload);
		PIN(bpf_program__fd(skel->progs.udpgrm_getsockopt), bpf_pin_dir,
		    "getsockopt", do_reload);
		if (without_sendmsg == 0) {
			PIN(bpf_program__fd(skel->progs.udpgrm_udp4_sendmsg), bpf_pin_dir,
			    "udp4_sendmsg", do_reload);
			PIN(bpf_program__fd(skel->progs.udpgrm_udp6_sendmsg), bpf_pin_dir,
			    "udp6_sendmsg", do_reload);
		}
		PIN(bpf_program__fd(skel->progs.udpgrm_bpf_bind4), bpf_pin_dir,
		    "inet4_bind", do_reload);
		PIN(bpf_program__fd(skel->progs.udpgrm_bpf_bind6), bpf_pin_dir,
		    "inet6_bind", do_reload);

		sd_notify(0, "READY=1\n");
	}

	/* You can install hooks from bpffs, without going into daemon! */
	if (do_install != 0) {
		char *cgroup_path = NULL;
		int cg_fd = cgroup_from_paths(cgroup_paths, &cgroup_path, cgroup_self);

		if (cg_fd < 0) {
			error(0, errno, "open(%s)", cgroup_paths[0]);
			retcode = EXIT_FAILURE;
			goto cleanup;
		}

		fprintf(stderr, "[ ] Installing BPF into cgroup %s\n", cgroup_path);

		/* Check for hook conflicts in the cgroup */
		int prog_fd = prog_from_cgroup(cg_fd, BPF_CGROUP_SETSOCKOPT,
					       "udpgrm_setsockopt", NULL);

		if (prog_fd != -1) {
			error(0, EUSERS,
			      "Looks like we are already loaded in that cgroup. Double "
			      "program install?");
		}

		struct stat sb;
		int r = fstat(cg_fd, &sb);
		if (r != 0)
			error(-1, errno, "fstat(%s)", cgroup_path);
		uint64_t cg_inode = sb.st_ino;

#define UNLOAD(directory, dir, suffix)                                                   \
	{                                                                                \
		char b[PATH_MAX];                                                        \
		snprintf(b, sizeof(b), "%s/%ld_%s", dir, cg_inode, suffix);              \
		int prog_fd = bpf_obj_get(b);                                            \
		if (prog_fd >= 0) {                                                      \
			bpf_link_detach(prog_fd);                                        \
			close(prog_fd);                                                  \
		}                                                                        \
		snprintf(b, sizeof(b), "%ld_%s", cg_inode, suffix);                      \
		unlinkat(dirfd(directory), b, 0);                                        \
	}

		DIR *const directory = opendir(bpf_pin_dir);
		if (directory != NULL) {
			UNLOAD(directory, bpf_pin_dir, "setsockopt");
			UNLOAD(directory, bpf_pin_dir, "getsockopt");
			UNLOAD(directory, bpf_pin_dir, "udp4_sendmsg");
			UNLOAD(directory, bpf_pin_dir, "udp6_sendmsg");
			UNLOAD(directory, bpf_pin_dir, "inet4_bind");
			UNLOAD(directory, bpf_pin_dir, "inet6_bind");
			closedir(directory);
		}

#define LOAD_AND_PIN(dir, suffix, cg_fd, prog, cg_id)                                    \
	{                                                                                \
		char b[PATH_MAX];                                                        \
		snprintf(b, sizeof(b), "%s/%s", dir, suffix);                            \
		int prog_fd = bpf_obj_get(b);                                            \
		if (prog_fd < 0)                                                         \
			error(-1, errno, "bpf_obj_get(%s)", b);                          \
		int link_fd = bpf_link_create(prog_fd, cg_fd, prog, NULL);               \
		if (link_fd < 0)                                                         \
			error(EXIT_FAILURE, errno, "bpf_link_create(" #prog ")");        \
		snprintf(b, sizeof(b), "%s/%ld_%s", dir, cg_inode, suffix);              \
		r = bpf_obj_pin(link_fd, b);                                             \
		if (r != 0)                                                              \
			error(-1, errno, "bpf_obj_pin(" #prog ")");                      \
		close(link_fd);                                                          \
	}

		LOAD_AND_PIN(bpf_pin_dir, "setsockopt", cg_fd, BPF_CGROUP_SETSOCKOPT,
			     cg_inode);
		LOAD_AND_PIN(bpf_pin_dir, "getsockopt", cg_fd, BPF_CGROUP_GETSOCKOPT,
			     cg_inode);
		if (without_sendmsg == 0) {
			LOAD_AND_PIN(bpf_pin_dir, "udp4_sendmsg", cg_fd,
				     BPF_CGROUP_UDP4_SENDMSG, cg_inode);
			LOAD_AND_PIN(bpf_pin_dir, "udp6_sendmsg", cg_fd,
				     BPF_CGROUP_UDP6_SENDMSG, cg_inode);
		}
		LOAD_AND_PIN(bpf_pin_dir, "inet4_bind", cg_fd, BPF_CGROUP_INET4_BIND,
			     cg_inode);
		LOAD_AND_PIN(bpf_pin_dir, "inet6_bind", cg_fd, BPF_CGROUP_INET6_BIND,
			     cg_inode);
	}

	if (do_daemon) {
		/* Disable line buffering of stdout, tests go to pipe
		 * and confuce glibc. */
		setbuf(stdout, NULL);

		if (tubular_path) {
			fprintf(stderr, "[ ] Tubular path %s ", tubular_path);
			if (access(tubular_path, W_OK) != 0) {
				fprintf(stderr, " (access failed, is tubular running?)");
			} else {
				fprintf(stderr, " (access ok)");
			}
			fprintf(stderr, "\n");
		}

		int signals[] = {SIGINT, SIGTERM};
		int signalfd = signal_desc(signals, 2);

		struct ring_buffer *msg = rb_setup_msg(tubular_path);
		int msg_fd = ring_buffer__epoll_fd(msg);

		while (1) {
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(signalfd, &rfds);
			FD_SET(msg_fd, &rfds);

			int max = MAX(signalfd, msg_fd) + 1;
			int r;
			if (reuseport_groups_empty()) {
				r = select(max, &rfds, NULL, NULL, NULL);
			} else {
				struct timeval timeout = {2, 0};
				r = select(max, &rfds, NULL, NULL, &timeout);
			}

			if (r == -1) {
				if (errno == EINTR)
					continue;
				error(-1, errno, "select()");
			}
			if (FD_ISSET(msg_fd, &rfds) != 0) {
				r = ring_buffer__consume(msg);
				if (r < 0) {
					error(-1, errno, "ring_buffer__consume");
				}
			}
			if (FD_ISSET(signalfd, &rfds) != 0) {
				break;
			}

			/* No more often than every 2 seconds */
			static time_t last_cleanup;
			if (time(NULL) - last_cleanup >= 2) {
				last_cleanup = time(NULL);
				reuseport_groups_maybe_cleanup_stale();
			}
		}

	cleanup:
		fprintf(stderr, "[ ] BPF fs cleanup rmdir %s\n", bpf_pin_dir);

		/* Generally don't error on directory cleanup errors */
		cleanup_bpf_pin_dir(bpf_pin_dir);

		ebpf__detach(skel);
		ebpf__destroy(skel);
	}

	return retcode;
}
