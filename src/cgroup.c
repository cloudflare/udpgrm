// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int prog_from_cgroup(int cg_fd, int prog_type, char *prog_info_name,
		     struct bpf_prog_info *user_info)
{
	uint32_t prog_ids[128];
	uint32_t prog_ids_sz = 128;
	int r = bpf_prog_query(cg_fd, prog_type, 0, NULL, prog_ids, &prog_ids_sz);
	if (r != 0)
		error(-1, errno, "bpf_prog_query(cgroup)");

	int i;
	for (i = 0; i < (int)prog_ids_sz; i++) {
		struct bpf_prog_info info = {};
		if (user_info) // needed for prog.map_ids
			info = *user_info;
		uint32_t info_len = sizeof(info);
		int prog_fd = bpf_prog_get_fd_by_id(prog_ids[i]);
		if (prog_fd < 0)
			error(-1, errno, "bpf_prog_get_fd_by_id");
		r = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
		if (r != 0)
			error(-1, errno, "bpf_prog_get_info_by_fd");
		if (strncmp(info.name, prog_info_name, BPF_OBJ_NAME_LEN - 1) == 0) {
			if (user_info)
				*user_info = info;
			return prog_fd;
		}
		close(prog_fd);
	}
	return -1;
}

static char *get_first_proc_self_cgroup()
{
	char line[PATH_MAX * 2] = {};
	char *cgroup_path = NULL;

	FILE *file = fopen("/proc/self/cgroup", "r");
	if (file == NULL) {
		error(-1, errno, "fopen");
	}

	while (fgets(line, sizeof(line), file)) {
		char *path = strchr(line, '/');
		if (path) {
			while (path && strlen(path) > 1 &&
			       path[strlen(path) - 1] == '\n') {
				path[strlen(path) - 1] = '\x00';
			}
			cgroup_path = strdup(path);
			break;
		}
	}

	fclose(file);
	return cgroup_path;
}

int cgroup_from_paths(char **cgroup_paths, char **selected_cgroup_path, int cgroup_self)
{
	char *main_cgroup_path = NULL;
	int cg_fd = -1;
	int i;
	for (i = 0; cgroup_paths[i] != NULL; i++) {
		cg_fd = open(cgroup_paths[i], O_DIRECTORY | O_RDONLY);
		if (cg_fd >= 0) {
			main_cgroup_path = cgroup_paths[i];
			goto maybe_self;
		}
	}
	return -1;

maybe_self:
	if (cgroup_self == 0) {
		if (selected_cgroup_path)
			*selected_cgroup_path = strdup(main_cgroup_path);
		return cg_fd;
	}
	close(cg_fd);
	char path[PATH_MAX] = {};
	char *child_cgroup = get_first_proc_self_cgroup();
	if (child_cgroup == NULL) {
		error(-1, ENOENT, "open(/proc/self/cgroup) parsing failed");
	}
	snprintf(path, sizeof(path), "%s%s", main_cgroup_path, child_cgroup);
	free(child_cgroup);
	cg_fd = open(path, O_DIRECTORY | O_RDONLY);
	if (cg_fd >= 0) {
		if (selected_cgroup_path)
			*selected_cgroup_path = strdup(path);
		return cg_fd;
	}
	error(0, ENOENT, "open(%s) failed", path);
	return -1;
}

void cleanup_bpf_pin_dir(char *bpf_pin_dir)
{
	/* Generally don't error on directory cleanup errors */
	DIR *const directory = opendir(bpf_pin_dir);
	if (directory) {
		struct dirent *entry;
		while ((entry = readdir(directory))) {
			if (entry->d_name[0] == '.') {
				continue;
			}
			/* We must explicitly detach the link,
			 * otherwise the detach is done by
			 * some delayed GC in the kernel and
			 * takes some time after program exit
			 * causing races in tests. */
			char b[PATH_MAX];
			snprintf(b, sizeof(b), "%s/%s", bpf_pin_dir, entry->d_name);
			int fd = bpf_obj_get(b);
			if (fd >= 0) {
				bpf_link_detach(fd);
				close(fd);
			}

			unlinkat(dirfd(directory), entry->d_name, 0);
		}
		closedir(directory);
	}

	rmdir(bpf_pin_dir);
}
