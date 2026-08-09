// SPDX-License-Identifier: Apache-2.0

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static _Atomic uint32_t expected_detach_program_id;
static _Atomic uint32_t expected_attach_ifindex;
static _Atomic uint32_t recovery_program_id;
static _Atomic uint32_t recovery_program_flags;
static _Atomic uint32_t owned_program_id;
static _Atomic uint32_t owned_program_ifindex;
static _Atomic uint32_t owned_program_flags;
static _Atomic uint64_t attach_call_count;
static _Atomic uint64_t detach_call_count;
#ifdef LMYZMAIL_XDP_TEST_HOOKS
static _Atomic int pause_after_attach;
static _Atomic int attach_is_paused;
static _Atomic int next_detach_error;
#endif

struct expected_map {
    const char *name;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    int pinned;
    int program_used;
};

static const struct expected_map expected_maps[] = {
    {"blocked_ips", BPF_MAP_TYPE_HASH, 4, 16, 100000, 0, 1, 1},
    {"blocked_ips_v6", BPF_MAP_TYPE_HASH, 16, 16, 100000, 0, 1, 1},
    {"whitelist_v4", BPF_MAP_TYPE_LPM_TRIE, 8, 1, 10000,
     BPF_F_NO_PREALLOC, 1, 1},
    {"whitelist_v6", BPF_MAP_TYPE_LPM_TRIE, 20, 1, 10000,
     BPF_F_NO_PREALLOC, 1, 1},
    {"stats", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 8, 0, 1, 1},
    {"config_map", BPF_MAP_TYPE_ARRAY, 4, 16, 1, 0, 0, 0},
    {"per_ip_stats_v4", BPF_MAP_TYPE_LRU_HASH, 4, 16, 50000, 0, 0, 1},
    {"per_ip_stats_v6", BPF_MAP_TYPE_LRU_HASH, 16, 16, 50000, 0, 0, 1},
};

#define EXPECTED_PROGRAM_NAME "xdp_firewall_pr"
#define XDP_MODE_MASK \
    (XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE)

int __real_bpf_xdp_attach(int ifindex, int prog_fd, uint32_t flags,
                          const struct bpf_xdp_attach_opts *opts);
int __real_bpf_xdp_detach(int ifindex, uint32_t flags,
                          const struct bpf_xdp_attach_opts *opts);

static int normalize_libbpf_result(int result) {
    if (result < 0) {
        return result;
    }
    return errno == 0 ? -EIO : -errno;
}

static void record_owned_program(uint32_t program_id, uint32_t ifindex,
                                 uint32_t flags) {
    atomic_store_explicit(&owned_program_ifindex, ifindex,
                          memory_order_relaxed);
    atomic_store_explicit(&owned_program_flags, flags, memory_order_relaxed);
    atomic_store_explicit(&owned_program_id, program_id, memory_order_release);
}

static void clear_owned_program(void) {
    atomic_store_explicit(&owned_program_id, 0, memory_order_release);
    atomic_store_explicit(&owned_program_ifindex, 0, memory_order_relaxed);
    atomic_store_explicit(&owned_program_flags, 0, memory_order_relaxed);
}

static void test_pause_after_attach(void) {
#ifdef LMYZMAIL_XDP_TEST_HOOKS
    if (!atomic_load_explicit(&pause_after_attach, memory_order_acquire)) {
        return;
    }
    atomic_store_explicit(&attach_is_paused, 1, memory_order_release);
    while (atomic_load_explicit(&pause_after_attach, memory_order_acquire)) {
        sched_yield();
    }
    atomic_store_explicit(&attach_is_paused, 0, memory_order_release);
#endif
}

#ifdef LMYZMAIL_XDP_TEST_HOOKS
void lmyzmail_xdp_test_pause_after_attach(int pause) {
    atomic_store_explicit(&pause_after_attach, pause != 0,
                          memory_order_release);
}

int lmyzmail_xdp_test_attach_is_paused(void) {
    return atomic_load_explicit(&attach_is_paused, memory_order_acquire);
}

void lmyzmail_xdp_test_fail_next_detach(int error_number) {
    int value = error_number > 0 && error_number < 4096 ? error_number : EIO;
    atomic_store_explicit(&next_detach_error, value, memory_order_release);
}
#endif

int lmyzmail_xdp_prepare_attach(uint32_t ifindex, uint32_t recover_program_id,
                                uint32_t recover_flags) {
    if (ifindex == 0 || (recover_program_id == 0) != (recover_flags == 0) ||
        (recover_flags != 0 && recover_flags != XDP_FLAGS_SKB_MODE &&
         recover_flags != XDP_FLAGS_DRV_MODE &&
         recover_flags != XDP_FLAGS_HW_MODE)) {
        return -EINVAL;
    }
    if (atomic_load_explicit(&owned_program_id, memory_order_acquire) != 0) {
        return -EBUSY;
    }
    atomic_store_explicit(&expected_attach_ifindex, ifindex,
                          memory_order_release);
    atomic_store_explicit(&recovery_program_flags, recover_flags,
                          memory_order_relaxed);
    atomic_store_explicit(&recovery_program_id, recover_program_id,
                          memory_order_release);
    return 0;
}

void lmyzmail_xdp_reset_attach_guard(void) {
    if (atomic_load_explicit(&owned_program_id, memory_order_acquire) != 0) {
        return;
    }
    atomic_store_explicit(&expected_attach_ifindex, 0, memory_order_release);
    atomic_store_explicit(&recovery_program_id, 0, memory_order_release);
    atomic_store_explicit(&recovery_program_flags, 0, memory_order_relaxed);
}

int __wrap_bpf_xdp_attach(int ifindex, int prog_fd, uint32_t flags,
                          const struct bpf_xdp_attach_opts *opts) {
    struct bpf_prog_info info = {};
    uint32_t info_length = sizeof(info);
    uint32_t expected_ifindex;
    uint32_t recover_id;
    uint32_t recover_flags;
    uint32_t mode;
    int result;

    atomic_fetch_add_explicit(&attach_call_count, 1, memory_order_relaxed);
    if (atomic_load_explicit(&owned_program_id, memory_order_acquire) != 0) {
        return -EBUSY;
    }
    expected_ifindex = atomic_load_explicit(&expected_attach_ifindex,
                                            memory_order_acquire);
    if (expected_ifindex == 0 || ifindex <= 0 ||
        (uint32_t)ifindex != expected_ifindex) {
        return -ESTALE;
    }
    mode = flags & XDP_MODE_MASK;
    if ((flags & ~XDP_MODE_MASK) != 0 ||
        (mode != XDP_FLAGS_SKB_MODE && mode != XDP_FLAGS_DRV_MODE &&
         mode != XDP_FLAGS_HW_MODE)) {
        return -EINVAL;
    }
    result = bpf_obj_get_info_by_fd(prog_fd, &info, &info_length);
    if (result != 0) {
        return normalize_libbpf_result(result);
    }
    if (info.id == 0 || info.type != BPF_PROG_TYPE_XDP) {
        return -EINVAL;
    }

    recover_id = atomic_load_explicit(&recovery_program_id,
                                      memory_order_acquire);
    recover_flags = atomic_load_explicit(&recovery_program_flags,
                                         memory_order_relaxed);
    if (recover_id != 0) {
        struct bpf_prog_info existing_info = {};
        uint32_t existing_info_length = sizeof(existing_info);
        uint32_t current_id = 0;
        int existing_fd;

        if (mode != recover_flags) {
            return -EOPNOTSUPP;
        }
        result = bpf_xdp_query_id(ifindex, mode, &current_id);
        if (result != 0) {
            return normalize_libbpf_result(result);
        }
        if (current_id != recover_id) {
            return -ESTALE;
        }
        existing_fd = bpf_prog_get_fd_by_id(recover_id);
        if (existing_fd < 0) {
            return -errno;
        }
        result = bpf_obj_get_info_by_fd(existing_fd, &existing_info,
                                        &existing_info_length);
        close(existing_fd);
        if (result != 0) {
            return normalize_libbpf_result(result);
        }
        if (existing_info.type != info.type ||
            strncmp((const char *)existing_info.name, (const char *)info.name,
                    BPF_OBJ_NAME_LEN) != 0 ||
            memcmp(existing_info.tag, info.tag, BPF_TAG_SIZE) != 0) {
            return -ESTALE;
        }
        record_owned_program(recover_id, expected_ifindex, mode);
        test_pause_after_attach();
        return 0;
    }

    result = __real_bpf_xdp_attach(
        ifindex, prog_fd, flags | XDP_FLAGS_UPDATE_IF_NOEXIST, opts);
    if (result != 0) {
        return normalize_libbpf_result(result);
    }
    record_owned_program(info.id, expected_ifindex, mode);
    test_pause_after_attach();
    return 0;
}

void lmyzmail_xdp_set_expected_detach_program_id(uint32_t program_id) {
    atomic_store_explicit(&expected_detach_program_id, program_id,
                          memory_order_release);
}

uint32_t lmyzmail_xdp_owned_program_id(void) {
    return atomic_load_explicit(&owned_program_id, memory_order_acquire);
}

uint32_t lmyzmail_xdp_owned_program_ifindex(void) {
    return atomic_load_explicit(&owned_program_ifindex, memory_order_relaxed);
}

uint32_t lmyzmail_xdp_owned_program_flags(void) {
    return atomic_load_explicit(&owned_program_flags, memory_order_relaxed);
}

uint64_t lmyzmail_xdp_attach_calls(void) {
    return atomic_load_explicit(&attach_call_count, memory_order_relaxed);
}

uint64_t lmyzmail_xdp_detach_calls(void) {
    return atomic_load_explicit(&detach_call_count, memory_order_relaxed);
}

static int map_info_matches(const struct bpf_map_info *info,
                            const struct expected_map *expected) {
    return strncmp((const char *)info->name, expected->name,
                   BPF_OBJ_NAME_LEN) == 0 &&
           info->type == expected->type &&
           info->key_size == expected->key_size &&
           info->value_size == expected->value_size &&
           info->max_entries == expected->max_entries &&
           info->map_flags == expected->map_flags;
}

static int map_info_by_fd(int fd, struct bpf_map_info *info) {
    uint32_t info_length = sizeof(*info);
    int result = bpf_obj_get_info_by_fd(fd, info, &info_length);
    return result == 0 ? 0 : normalize_libbpf_result(result);
}

static int pinned_map_info(const char *pin_path,
                           const struct expected_map *expected,
                           struct bpf_map_info *info) {
    char path[512];
    int fd;
    int result;

    if (snprintf(path, sizeof(path), "%s/%s", pin_path, expected->name) >=
        (int)sizeof(path)) {
        return -ENAMETOOLONG;
    }
    fd = bpf_obj_get(path);
    if (fd < 0) {
        return -errno;
    }
    result = map_info_by_fd(fd, info);
    close(fd);
    return result;
}

int lmyzmail_xdp_validate_pinned_maps(const char *pin_path, int require_all) {
    if (pin_path == NULL) {
        return -EINVAL;
    }
    for (size_t index = 0;
         index < sizeof(expected_maps) / sizeof(expected_maps[0]); index++) {
        const struct expected_map *expected = &expected_maps[index];
        struct bpf_map_info info = {};
        int result;

        if (!expected->pinned) {
            continue;
        }
        result = pinned_map_info(pin_path, expected, &info);
        if (result == -ENOENT && !require_all) {
            continue;
        }
        if (result != 0) {
            return result;
        }
        if (!map_info_matches(&info, expected)) {
            return -EINVAL;
        }
    }
    return 0;
}

static int program_info_with_map_ids(int program_fd,
                                     struct bpf_prog_info *info,
                                     uint32_t **map_ids) {
    uint32_t info_length = sizeof(*info);
    uint32_t count;
    int result;

    memset(info, 0, sizeof(*info));
    result = bpf_obj_get_info_by_fd(program_fd, info, &info_length);
    if (result != 0) {
        return normalize_libbpf_result(result);
    }
    count = info->nr_map_ids;
    if (count == 0 || count > 64) {
        return -EINVAL;
    }
    *map_ids = calloc(count, sizeof(**map_ids));
    if (*map_ids == NULL) {
        return -ENOMEM;
    }
    memset(info, 0, sizeof(*info));
    info->nr_map_ids = count;
    info->map_ids = (uint64_t)(uintptr_t)*map_ids;
    info_length = sizeof(*info);
    result = bpf_obj_get_info_by_fd(program_fd, info, &info_length);
    if (result != 0) {
        free(*map_ids);
        *map_ids = NULL;
        return normalize_libbpf_result(result);
    }
    if (info->nr_map_ids != count) {
        free(*map_ids);
        *map_ids = NULL;
        return -ESTALE;
    }
    return 0;
}

static int validate_program_fd(const char *pin_path, int program_fd) {
    struct bpf_prog_info program_info = {};
    uint32_t *map_ids = NULL;
    uint32_t matched_ids[sizeof(expected_maps) / sizeof(expected_maps[0])] = {};
    size_t expected_count = sizeof(expected_maps) / sizeof(expected_maps[0]);
    size_t expected_program_count = 0;
    int result;

    for (size_t index = 0; index < expected_count; index++) {
        expected_program_count += expected_maps[index].program_used != 0;
    }

    result = program_info_with_map_ids(program_fd, &program_info, &map_ids);
    if (result != 0) {
        return result;
    }
    if (program_info.type != BPF_PROG_TYPE_XDP ||
        strncmp((const char *)program_info.name, EXPECTED_PROGRAM_NAME,
                BPF_OBJ_NAME_LEN) != 0 ||
        program_info.nr_map_ids != expected_program_count) {
        free(map_ids);
        return -EINVAL;
    }
    for (uint32_t map_index = 0; map_index < program_info.nr_map_ids;
         map_index++) {
        struct bpf_map_info map_info = {};
        int map_fd = bpf_map_get_fd_by_id(map_ids[map_index]);
        size_t expected_index;

        if (map_fd < 0) {
            result = -errno;
            free(map_ids);
            return result;
        }
        result = map_info_by_fd(map_fd, &map_info);
        close(map_fd);
        if (result != 0) {
            free(map_ids);
            return result;
        }
        for (expected_index = 0; expected_index < expected_count;
             expected_index++) {
            if (expected_maps[expected_index].program_used &&
                map_info_matches(&map_info, &expected_maps[expected_index])) {
                break;
            }
        }
        if (expected_index == expected_count ||
            matched_ids[expected_index] != 0) {
            free(map_ids);
            return -EINVAL;
        }
        matched_ids[expected_index] = map_info.id;
    }
    free(map_ids);

    for (size_t index = 0; index < expected_count; index++) {
        const struct expected_map *expected = &expected_maps[index];
        struct bpf_map_info pin_info = {};

        if (expected->program_used && matched_ids[index] == 0) {
            return -EINVAL;
        }
        if (!expected->program_used) {
            continue;
        }
        if (!expected->pinned) {
            continue;
        }
        result = pinned_map_info(pin_path, expected, &pin_info);
        if (result != 0) {
            return result;
        }
        if (!map_info_matches(&pin_info, expected) ||
            pin_info.id != matched_ids[index]) {
            return -ESTALE;
        }
    }
    return 0;
}

int lmyzmail_xdp_validate_program(const char *pin_path,
                                  uint32_t program_id) {
    int program_fd;
    int result;

    if (pin_path == NULL || program_id == 0) {
        return -EINVAL;
    }
    program_fd = bpf_prog_get_fd_by_id(program_id);
    if (program_fd < 0) {
        return -errno;
    }
    result = validate_program_fd(pin_path, program_fd);
    close(program_fd);
    return result;
}

static void close_map_fds(int *fds, size_t count) {
    for (size_t index = 0; index < count; index++) {
        if (fds[index] >= 0) {
            close(fds[index]);
            fds[index] = -1;
        }
    }
}

static int recovery_map_fds(uint32_t program_id, int *fds, size_t count) {
    struct bpf_prog_info program_info = {};
    uint32_t *map_ids = NULL;
    int program_fd;
    int result;

    if (program_id == 0 || count != sizeof(expected_maps) / sizeof(expected_maps[0])) {
        return -EINVAL;
    }
    for (size_t index = 0; index < count; index++) {
        fds[index] = -1;
    }
    program_fd = bpf_prog_get_fd_by_id(program_id);
    if (program_fd < 0) {
        return -errno;
    }
    result = program_info_with_map_ids(program_fd, &program_info, &map_ids);
    close(program_fd);
    if (result != 0) {
        return result;
    }
    for (uint32_t map_index = 0; map_index < program_info.nr_map_ids;
         map_index++) {
        struct bpf_map_info info = {};
        int map_fd = bpf_map_get_fd_by_id(map_ids[map_index]);

        if (map_fd < 0) {
            result = -errno;
            goto cleanup;
        }
        result = map_info_by_fd(map_fd, &info);
        if (result != 0) {
            close(map_fd);
            goto cleanup;
        }
        for (size_t index = 0; index < count; index++) {
            const struct expected_map *expected = &expected_maps[index];
            if (expected->program_used && !expected->pinned &&
                map_info_matches(&info, expected)) {
                if (fds[index] >= 0) {
                    close(map_fd);
                    result = -EINVAL;
                    goto cleanup;
                }
                fds[index] = map_fd;
                map_fd = -1;
                break;
            }
        }
        if (map_fd >= 0) {
            close(map_fd);
        }
    }
    for (size_t index = 0; index < count; index++) {
        const struct expected_map *expected = &expected_maps[index];
        if (expected->program_used && !expected->pinned && fds[index] < 0) {
            result = -EINVAL;
            goto cleanup;
        }
    }
    free(map_ids);
    return 0;

cleanup:
    free(map_ids);
    close_map_fds(fds, count);
    return result;
}

static int recovery_map_path(char *path, size_t length,
                             const char *pin_path,
                             const struct expected_map *expected) {
    int written = snprintf(path, length, "%s/%s", pin_path, expected->name);
    return written < 0 || (size_t)written >= length ? -ENAMETOOLONG : 0;
}

int lmyzmail_xdp_stage_recovery_maps(const char *pin_path,
                                     uint32_t program_id) {
    size_t count = sizeof(expected_maps) / sizeof(expected_maps[0]);
    int fds[sizeof(expected_maps) / sizeof(expected_maps[0])];
    int staged[sizeof(expected_maps) / sizeof(expected_maps[0])] = {};
    int result;

    if (pin_path == NULL) {
        return -EINVAL;
    }
    result = recovery_map_fds(program_id, fds, count);
    if (result != 0) {
        return result;
    }
    for (size_t index = 0; index < count; index++) {
        const struct expected_map *expected = &expected_maps[index];
        char path[512];

        if (!expected->program_used || expected->pinned) {
            continue;
        }
        result = recovery_map_path(path, sizeof(path), pin_path, expected);
        if (result != 0) {
            goto cleanup;
        }
        if (bpf_obj_pin(fds[index], path) != 0) {
            result = -errno;
            goto cleanup;
        }
        staged[index] = 1;
    }
    result = 0;

cleanup:
    if (result != 0) {
        for (size_t index = 0; index < count; index++) {
            const struct expected_map *expected = &expected_maps[index];
            char path[512];
            if (staged[index] != 0 &&
                recovery_map_path(path, sizeof(path), pin_path, expected) == 0) {
                unlink(path);
            }
        }
    }
    close_map_fds(fds, count);
    return result;
}

int lmyzmail_xdp_unstage_recovery_maps(const char *pin_path,
                                       uint32_t program_id) {
    size_t count = sizeof(expected_maps) / sizeof(expected_maps[0]);
    int fds[sizeof(expected_maps) / sizeof(expected_maps[0])];
    int result;

    if (pin_path == NULL) {
        return -EINVAL;
    }
    result = recovery_map_fds(program_id, fds, count);
    if (result != 0) {
        return result;
    }
    for (size_t index = 0; index < count; index++) {
        const struct expected_map *expected = &expected_maps[index];
        struct bpf_map_info expected_info = {};
        struct bpf_map_info pinned_info = {};
        char path[512];
        int pinned_fd;

        if (!expected->program_used || expected->pinned) {
            continue;
        }
        result = recovery_map_path(path, sizeof(path), pin_path, expected);
        if (result != 0) {
            break;
        }
        result = map_info_by_fd(fds[index], &expected_info);
        if (result != 0) {
            break;
        }
        pinned_fd = bpf_obj_get(path);
        if (pinned_fd < 0) {
            result = -errno;
            break;
        }
        result = map_info_by_fd(pinned_fd, &pinned_info);
        close(pinned_fd);
        if (result != 0) {
            break;
        }
        if (!map_info_matches(&pinned_info, expected) ||
            pinned_info.id != expected_info.id) {
            result = -ESTALE;
            break;
        }
        if (unlink(path) != 0) {
            result = -errno;
            break;
        }
    }
    close_map_fds(fds, count);
    return result;
}

int lmyzmail_xdp_detach_owned(uint32_t expected) {
    uint32_t owned = atomic_load_explicit(&owned_program_id,
                                          memory_order_acquire);
    uint32_t ifindex;
    uint32_t flags;
    uint32_t current = 0;
    int program_fd;
    int result;

    atomic_fetch_add_explicit(&detach_call_count, 1, memory_order_relaxed);
    if (expected == 0) {
        return -EPERM;
    }
    if (owned == 0) {
        return 0;
    }
    if (expected != owned) {
        return -ESTALE;
    }
    ifindex = atomic_load_explicit(&owned_program_ifindex,
                                   memory_order_relaxed);
    flags = atomic_load_explicit(&owned_program_flags, memory_order_relaxed);
    if (ifindex == 0 || flags == 0) {
        return -EINVAL;
    }
    result = bpf_xdp_query_id(ifindex, flags, &current);
    if (result != 0) {
        return normalize_libbpf_result(result);
    }
    if (current != expected) {
        clear_owned_program();
        return -ESTALE;
    }
#ifdef LMYZMAIL_XDP_TEST_HOOKS
    result = atomic_exchange_explicit(&next_detach_error, 0,
                                      memory_order_acq_rel);
    if (result != 0) {
        return -result;
    }
#endif
    program_fd = bpf_prog_get_fd_by_id(expected);
    if (program_fd < 0) {
        return -errno;
    }
    LIBBPF_OPTS(bpf_xdp_attach_opts, guarded_opts, .old_prog_fd = program_fd);
    result = __real_bpf_xdp_detach(ifindex, flags, &guarded_opts);
    close(program_fd);
    if (result == 0) {
        clear_owned_program();
    } else {
        result = normalize_libbpf_result(result);
    }
    return result;
}

int __wrap_bpf_xdp_detach(int ifindex, uint32_t flags,
                          const struct bpf_xdp_attach_opts *opts) {
    uint32_t expected = atomic_load_explicit(&expected_detach_program_id,
                                             memory_order_acquire);
    uint32_t owned_ifindex = atomic_load_explicit(&owned_program_ifindex,
                                                  memory_order_relaxed);
    uint32_t owned_flags = atomic_load_explicit(&owned_program_flags,
                                                memory_order_relaxed);

    (void)opts;
    if (expected == 0 || ifindex <= 0 || (uint32_t)ifindex != owned_ifindex ||
        flags != owned_flags) {
        return -EPERM;
    }
    return lmyzmail_xdp_detach_owned(expected);
}
