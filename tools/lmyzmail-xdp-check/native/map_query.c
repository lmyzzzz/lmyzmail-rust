// SPDX-License-Identifier: Apache-2.0

#include <bpf/bpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

struct lmyz_xdp_map_info {
    uint32_t id;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    char name[BPF_OBJ_NAME_LEN];
};

int lmyz_xdp_map_get_next_id(uint32_t start_id, uint32_t *next_id) {
    if (next_id == NULL) {
        return -EINVAL;
    }
    if (bpf_map_get_next_id(start_id, next_id) == 0) {
        return 1;
    }
    return errno == ENOENT ? 0 : -errno;
}

static int map_info_from_fd(int fd, struct lmyz_xdp_map_info *out) {
    struct bpf_map_info info = {};
    uint32_t length = sizeof(info);

    if (out == NULL) {
        return -EINVAL;
    }
    if (bpf_obj_get_info_by_fd(fd, &info, &length) != 0) {
        return -errno;
    }
    memset(out, 0, sizeof(*out));
    out->id = info.id;
    out->type = info.type;
    out->key_size = info.key_size;
    out->value_size = info.value_size;
    out->max_entries = info.max_entries;
    out->map_flags = info.map_flags;
    memcpy(out->name, info.name, sizeof(out->name));
    return 0;
}

int lmyz_xdp_map_info_by_id(uint32_t id, struct lmyz_xdp_map_info *out) {
    int fd = bpf_map_get_fd_by_id(id);
    int result;

    if (fd < 0) {
        return -errno;
    }
    result = map_info_from_fd(fd, out);
    close(fd);
    return result;
}

int lmyz_xdp_map_info_by_pin(const char *path, struct lmyz_xdp_map_info *out) {
    int fd;
    int result;

    if (path == NULL) {
        return -EINVAL;
    }
    fd = bpf_obj_get(path);
    if (fd < 0) {
        return -errno;
    }
    result = map_info_from_fd(fd, out);
    close(fd);
    return result;
}
