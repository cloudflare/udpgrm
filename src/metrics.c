#include <bpf/bpf.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>

#include "common.h"

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "dev"
#endif

void init_metrics(int prog_fd)
{
	int metrics_map_fd = map_from_prog(prog_fd, "metrics_map", NULL);
	if (metrics_map_fd < 0)
		error(-1, errno, "map_from_prog()");

	unsigned int metrics_key = 0;
	metrics_t metrics_value = {0};
	strncpy(metrics_value.package_version, PACKAGE_VERSION,
		sizeof(metrics_value.package_version) - 1);

	int r = bpf_map_update_elem(metrics_map_fd, &metrics_key, &metrics_value, 0);
	if (r < 0)
		error(-1, r, "bpf_map_update_elem()");
}

metrics_t get_metrics(int prog_fd)
{
	int metrics_map_fd = map_from_prog(prog_fd, "metrics_map", NULL);
	if (metrics_map_fd < 0)
		error(-1, errno, "map_from_prog()");

	unsigned int metrics_key = 0;
	metrics_t metrics_value;

	int r = bpf_map_lookup_elem(metrics_map_fd, &metrics_key, &metrics_value);
	if (r < 0)
		error(-1, r, "bpf_map_lookup_elem()");

	return metrics_value;
}

void do_socket_metrics(struct reuseport_storage_key *key, struct reuseport_storage *s)
{
	char *t = key_to_str(key);

	uint32_t max_apps = s->dis.max_apps;
	if (max_apps == 0) {
		max_apps = 1;
	}

	for (uint32_t app_idx = 0; app_idx < max_apps; app_idx++) {
		printf("working_gen{socket=\"%s\",app_idx=\"%d\"} %d\n", t, app_idx,
		       s->working_gen[app_idx]);
	}

#define METRIC(token)                                                                    \
	if (s->token > 0) {                                                              \
		printf(#token "{socket=\"%s\"} %lu\n", t, s->token);                     \
	}

	METRIC(socket_critical_gauge);
	METRIC(socket_critical);

	METRIC(rx_processed_total);
	METRIC(rx_internal_state_error);
	METRIC(rx_cbpf_prog_error);
	METRIC(rx_packet_too_short_error);

	METRIC(rx_dissected_ok_total);
	METRIC(rx_flow_ok);
	METRIC(rx_flow_rg_conflict);
	METRIC(rx_flow_other_error);
	METRIC(rx_flow_new_unseen);
	METRIC(rx_flow_new_had_expired);
	METRIC(rx_flow_new_bad_cookie);

	METRIC(rx_new_flow_total);
	METRIC(rx_new_flow_working_gen_dispatch_ok);
	METRIC(rx_new_flow_working_gen_dispatch_error);

	METRIC(tx_total);
	METRIC(tx_flow_create_ok);
	METRIC(tx_flow_create_from_expired_ok);
	METRIC(tx_flow_create_error);
	METRIC(tx_flow_update_ok);
	METRIC(tx_flow_update_conflict);
}

void do_metrics(int prog_fd, int map_fd)
{
	int metrics_map_fd = map_from_prog(prog_fd, "metrics_map", NULL);
	if (metrics_map_fd < 0)
		error(-1, errno, "map_from_prog()");

	metrics_t metrics = get_metrics(prog_fd);

	printf("build_info{version=\"%s\"} 1\n", metrics.package_version);

	struct reuseport_storage_key key = {};
	int err = 0;
	bpf_map_get_next_key(map_fd, NULL, &key);
	while (!err) {
		struct reuseport_storage s = {};
		int r = bpf_map_lookup_elem(map_fd, &key, &s);
		if (r == 0) {
			do_socket_metrics(&key, &s);
		}

		err = bpf_map_get_next_key(map_fd, &key, &key);
	}
}