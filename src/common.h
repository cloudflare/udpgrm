// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include <getopt.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <linux/filter.h>

#include "../include/udpgrm_internal.h"

#ifndef IP_PKTINFO
#define IP_PKTINFO 8
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* utils.c */
const char *optstring_from_long_options(const struct option *opt);
void setup_itimer(int seconds, int *tick);
void setup_ctrlc(int *done);
int signal_desc(int *sig, int sig_num);

uint64_t suffix(uint64_t n, char **suffix);
int poke_cmsg(struct msghdr *msgh, int single_ctrl_sz);
int set_timstamp_cmsg(struct msghdr *msgh, int single_ctrl_sz);
int print_cmsg(struct msghdr *msgh);
int get_tx_timespec(struct msghdr *msgh, struct timespec *tx, int *type, int *pkt_idx);
int get_rx_timespec(struct msghdr *msgh, struct timespec *tx);

int gro_to_packets(int gro_sz, int bytes);
int fprintf_hex(FILE *out, char *desc, void *addr, int len);
int mirror_packet(uint8_t *data, int data_len, uint16_t port);

size_t snprintfcat(char *buf, size_t size, char const *fmt, ...);
void bump_memlock_rlimit(void);

/* net.c */
socklen_t net_ss_size(struct sockaddr_storage *ss);
int net_get_port(struct sockaddr_storage *ss);
const char *net_ss_ntop(struct sockaddr_storage *ss, int show_port);
int net_parse_sockaddr(struct sockaddr_storage *ss, const char *addr, int default_port);

int net_gethostbyname(struct sockaddr_storage *ss, const char *host, int port,
		      int force_family);

/* pidfd.c */
int pidfd_open(pid_t pid, unsigned int flags);
int pidfd_find_socket(int pidfd, int max_continous_gap, int type, int protocol,
		      struct sockaddr_storage *addr, uint64_t cookie);

/* uspace.c */
struct reuseport_storage;
void cookies_find_empty(struct reuseport_storage *state, int gen, int sockhash_fd,
			uint64_t cookie, int *prev_pos, int *free_pos, int *gen_len);

struct msg_value;
void run_cb_update_map(struct msg_value *msg);
struct reuseport_storage_key;
void metric_incr_critical(const struct reuseport_storage_key *skey, int counter,
			  int gauge);

struct bpf_map_info;
int map_from_prog(int prog_fd, char *map_name, struct bpf_map_info *user_map_info);
struct sockaddr_storage;
void skey_from_ss(struct reuseport_storage_key *skey, struct sockaddr_storage *ss);

int *map_by_name(char *map_name, uint32_t skip_id);
uint32_t map_fd_to_id(int map_fd);

/* cgroup.c */
struct bpf_prog_info;
int prog_from_cgroup(int cg_fd, int prog_type, char *prog_info_name,
		     struct bpf_prog_info *user_info);
int cgroup_from_paths(char **cgroup_paths, char **selected_cgroup_path, int cgroup_self);
void cleanup_bpf_pin_dir(char *bpf_pin_dir);

/* tubular.c */
int tubular_maybe_preserve_fd(struct reuseport_storage *state, int gen, int gen_len,
			      int free_pos, int f);
int tubular_maybe_register(struct reuseport_storage *state, int wg, char *tubular_path);
void reuseport_groups_maybe_cleanup_stale();
int reuseport_groups_empty();

/* do_list.c */
char *key_to_str(struct reuseport_storage_key *key);
void do_list(int prog_fd, int map_fd, struct sockaddr_storage *reuseport_ss, int verbose);

/* do_flows.c */
void do_flows(int prog_fd, int map_fd, struct sockaddr_storage *reuseport_ss,
	      int verbose);

/* metrics.c */
void init_metrics(int prog_fd);
metrics_t get_metrics(int prog_fd);
void do_metrics(int prog_fd, int map_fd);
