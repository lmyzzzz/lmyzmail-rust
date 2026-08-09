// SPDX-License-Identifier: Apache-2.0
// XDP Firewall 用户态实现 - 增强版 v1.1
// 
// 新增功能：
//   - 动态白名单管理（CIDR 支持）
//   - PPS/SYN PPS 统计
//   - Per-IP 统计（用于单IP PPS检测）
//   - 增强的 map 复用和兼容性处理

#define _GNU_SOURCE
#include "xdp_firewall.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <time.h>
#include <sys/capability.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// ============================================================================
// 内部常量
// ============================================================================

#define VERSION "1.1.0"
#define DEFAULT_PIN_PATH "/sys/fs/bpf/lmyzmail"
#define DEFAULT_PROG_NAME "xdp_firewall_prog"
#define ERROR_BUF_SIZE 512

// Map 名称（必须与 BPF 程序中定义一致）
#define MAP_BLOCKED_IPS     "blocked_ips"
#define MAP_BLOCKED_IPS_V6  "blocked_ips_v6"
#define MAP_WHITELIST_V4    "whitelist_v4"
#define MAP_WHITELIST_V6    "whitelist_v6"
#define MAP_STATS           "stats"
#define MAP_CONFIG          "config_map"
#define MAP_PER_IP_STATS_V4  "per_ip_stats_v4"
#define MAP_PER_IP_STATS_V6  "per_ip_stats_v6"

// 统计索引（与 BPF 程序一致）
#define STATS_PASSED        0
#define STATS_DROPPED       1
#define STATS_TOTAL         2
#define STATS_TCP_SYN       3
#define STATS_WHITELISTED   4
#define STATS_MAX           8

// ============================================================================
// 内部数据结构
// ============================================================================

// LPM Key 结构（必须与 BPF 程序一致）
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 addr[16];
};

// Per-IP 统计（必须与 BPF 程序一致）
struct per_ip_stats {
    uint64_t packets;
    uint64_t syn_packets;
};

// PPS 统计基准
struct pps_baseline {
    uint64_t total;
    uint64_t syn;
    uint64_t dropped;
    uint64_t passed;
    uint64_t timestamp_ns;
};

// ============================================================================
// 全局状态（单例模式）
// ============================================================================

static struct {
    // 初始化状态
    int initialized;
    int verbose;
    
    // BPF 对象
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    
    // Map 文件描述符
    int map_blocked_ips_fd;
    int map_blocked_ips_v6_fd;
    int map_whitelist_v4_fd;
    int map_whitelist_v6_fd;
    int map_stats_fd;
    int map_config_fd;
    int map_per_ip_stats_v4_fd;
    int map_per_ip_stats_v6_fd;
    
    // 网卡信息
    int ifindex;
    char ifname[IF_NAMESIZE];
    
    // Pin 路径
    char pin_path[256];
    
    // 附加模式
    int xdp_flags;
    
    // PPS 统计基准
    struct pps_baseline pps_baseline;
    
    // 错误信息
    char error_buf[ERROR_BUF_SIZE];
    
} g_ctx = {
    .map_blocked_ips_fd = -1,
    .map_blocked_ips_v6_fd = -1,
    .map_whitelist_v4_fd = -1,
    .map_whitelist_v6_fd = -1,
    .map_stats_fd = -1,
    .map_config_fd = -1,
    .map_per_ip_stats_v4_fd = -1,
    .map_per_ip_stats_v6_fd = -1,
};

// ============================================================================
// 内部辅助函数
// ============================================================================

#define LOG(fmt, ...) \
    do { if (g_ctx.verbose) fprintf(stderr, "[XDP-FW] " fmt "\n", ##__VA_ARGS__); } while(0)

#define LOG_ERR(fmt, ...) \
    fprintf(stderr, "[XDP-FW ERROR] " fmt "\n", ##__VA_ARGS__)

#define SET_ERROR(fmt, ...) \
    snprintf(g_ctx.error_buf, ERROR_BUF_SIZE, fmt, ##__VA_ARGS__)

// 获取当前时间戳（纳秒）- 使用 MONOTONIC 避免时间跳变
static inline uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// 获取实时时间戳（用于封禁记录）
static inline uint64_t get_realtime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// 确保 BPF 文件系统已挂载
static int ensure_bpf_fs(void) {
    struct stat st;
    if (stat("/sys/fs/bpf", &st) != 0) {
        SET_ERROR("BPF filesystem not mounted at /sys/fs/bpf. Run: mount -t bpf bpf /sys/fs/bpf");
        return -1;
    }
    return 0;
}

// 创建 pin 目录
static int create_pin_dir(const char *path) {
    char dir[256];
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    
    for (char *p = dir + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
                SET_ERROR("Failed to create directory %s: %s", dir, strerror(errno));
                return -1;
            }
            *p = '/';
        }
    }
    
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        SET_ERROR("Failed to create directory %s: %s", dir, strerror(errno));
        return -1;
    }
    
    return 0;
}

// 设置 RLIMIT_MEMLOCK
static int set_rlimit(void) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        LOG("Warning: Failed to set RLIMIT_MEMLOCK: %s", strerror(errno));
    }
    return 0;
}

// libbpf 日志回调
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (!g_ctx.verbose && level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

// 尝试复用已存在的 pinned map（增强版，带验证）
static int try_reuse_pinned_maps(void) {
    char path[512];
    int reused = 0;
    int fd;
    
    // blocked_ips - 核心 map，必须可复用
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_BLOCKED_IPS);
    fd = bpf_obj_get(path);
    if (fd >= 0) {
        g_ctx.map_blocked_ips_fd = fd;
        LOG("Reusing pinned blocked_ips map (fd=%d)", fd);
        reused = 1;
    } else {
        LOG("blocked_ips map not found or incompatible: %s", strerror(errno));
    }
    
    // blocked_ips_v6
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_BLOCKED_IPS_V6);
    fd = bpf_obj_get(path);
    if (fd >= 0) {
        g_ctx.map_blocked_ips_v6_fd = fd;
        LOG("Reusing pinned blocked_ips_v6 map (fd=%d)", fd);
    } else {
        LOG("blocked_ips_v6 map not found, will create new");
    }
    
    // whitelist_v4 - LPM Trie，可能不存在于旧版本
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_WHITELIST_V4);
    fd = bpf_obj_get(path);
    if (fd >= 0) {
        g_ctx.map_whitelist_v4_fd = fd;
        LOG("Reusing pinned whitelist_v4 map (fd=%d)", fd);
    } else {
        LOG("whitelist_v4 map not found (errno=%d), will create new", errno);
    }
    
    // whitelist_v6 - LPM Trie，可能不存在于旧版本
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_WHITELIST_V6);
    fd = bpf_obj_get(path);
    if (fd >= 0) {
        g_ctx.map_whitelist_v6_fd = fd;
        LOG("Reusing pinned whitelist_v6 map (fd=%d)", fd);
    } else {
        LOG("whitelist_v6 map not found (errno=%d), will create new", errno);
    }
    
    // stats - 可能结构已变化
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_STATS);
    fd = bpf_obj_get(path);
    if (fd >= 0) {
        g_ctx.map_stats_fd = fd;
        LOG("Reusing pinned stats map (fd=%d)", fd);
    } else {
        LOG("stats map not found, will create new");
    }
    
    // per_ip_stats_v4 - LRU map，通常不需要持久化
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_PER_IP_STATS_V4);
    fd = bpf_obj_get(path);
    if (fd >= 0) {
        g_ctx.map_per_ip_stats_v4_fd = fd;
        LOG("Reusing pinned per_ip_stats_v4 map (fd=%d)", fd);
    }
    
    // per_ip_stats_v6
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_PER_IP_STATS_V6);
    fd = bpf_obj_get(path);
    if (fd >= 0) {
        g_ctx.map_per_ip_stats_v6_fd = fd;
        LOG("Reusing pinned per_ip_stats_v6 map (fd=%d)", fd);
    }
    
    return reused;
}

// 将主机字节序 IP 转换为 map key（网络字节序）
static inline __u32 ip_to_map_key(uint32_t ip_host_order) {
    return htonl(ip_host_order);
}

// 将 map key（网络字节序）转换回主机字节序
static inline uint32_t map_key_to_ip(__u32 key) {
    return ntohl(key);
}

// 获取所有 CPU 的统计总和
static int get_percpu_stats_sum(int map_fd, __u32 key, uint64_t *out) {
    if (map_fd < 0 || !out) return -1;
    
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) num_cpus = 1;
    
    uint64_t *values = calloc(num_cpus, sizeof(uint64_t));
    if (!values) return -1;
    
    *out = 0;
    if (bpf_map_lookup_elem(map_fd, &key, values) == 0) {
        for (int i = 0; i < num_cpus; i++) {
            *out += values[i];
        }
    }
    
    free(values);
    return 0;
}

// ============================================================================
// 公共 API 实现 - 初始化
// ============================================================================

int xdp_fw_init(const struct xdp_fw_opts *opts) {
    int err;
    struct bpf_map *map;
    
    // 检查重复初始化
    if (g_ctx.initialized) {
        SET_ERROR("XDP Firewall already initialized");
        return XDP_FW_ERR_ALREADY;
    }
    
    // 参数验证
    if (!opts || !opts->ifname || !opts->bpf_obj_path) {
        SET_ERROR("Invalid parameters: ifname and bpf_obj_path are required");
        return XDP_FW_ERR_INIT;
    }
    
    // 重置所有 map fd
    g_ctx.map_blocked_ips_fd = -1;
    g_ctx.map_blocked_ips_v6_fd = -1;
    g_ctx.map_whitelist_v4_fd = -1;
    g_ctx.map_whitelist_v6_fd = -1;
    g_ctx.map_stats_fd = -1;
    g_ctx.map_config_fd = -1;
    g_ctx.map_per_ip_stats_v4_fd = -1;
    g_ctx.map_per_ip_stats_v6_fd = -1;
    
    // 设置详细模式
    g_ctx.verbose = opts->verbose;
    libbpf_set_print(libbpf_print_fn);
    
    LOG("Initializing XDP Firewall v%s", VERSION);
    LOG("  Interface: %s", opts->ifname);
    LOG("  BPF Object: %s", opts->bpf_obj_path);
    
    // 检查权限
    if (!xdp_fw_check_permissions()) {
        SET_ERROR("Insufficient permissions. Need root or CAP_BPF+CAP_NET_ADMIN");
        return XDP_FW_ERR_PERM;
    }
    
    set_rlimit();
    
    if (ensure_bpf_fs() != 0) {
        return XDP_FW_ERR_INIT;
    }
    
    // 设置 pin 路径
    strncpy(g_ctx.pin_path, 
            opts->pin_base_path ? opts->pin_base_path : DEFAULT_PIN_PATH,
            sizeof(g_ctx.pin_path) - 1);
    
    if (create_pin_dir(g_ctx.pin_path) != 0) {
        return XDP_FW_ERR_INIT;
    }
    
    // 获取网卡索引
    strncpy(g_ctx.ifname, opts->ifname, IF_NAMESIZE - 1);
    g_ctx.ifindex = if_nametoindex(opts->ifname);
    if (g_ctx.ifindex == 0) {
        SET_ERROR("Interface '%s' not found", opts->ifname);
        return XDP_FW_ERR_NODEV;
    }
    LOG("Interface %s has index %d", opts->ifname, g_ctx.ifindex);
    
    // 尝试复用已有的 pinned maps
    int reused = try_reuse_pinned_maps();
    LOG("Reused %d existing pinned maps", reused);
    
    // 打开 BPF 对象（不使用 pin_root_path，手动处理 pinning）
    g_ctx.obj = bpf_object__open_file(opts->bpf_obj_path, NULL);
    err = libbpf_get_error(g_ctx.obj);
    if (err) {
        SET_ERROR("Failed to open BPF object '%s': %s", opts->bpf_obj_path, strerror(-err));
        g_ctx.obj = NULL;
        return XDP_FW_ERR_LOAD;
    }
    LOG("BPF object opened successfully");
    
    // 配置 map 复用（只复用成功获取的）
    if (g_ctx.map_blocked_ips_fd >= 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_BLOCKED_IPS);
        if (map) {
            err = bpf_map__reuse_fd(map, g_ctx.map_blocked_ips_fd);
            if (err) {
                LOG("Warning: Failed to reuse blocked_ips (err=%d), will create new", err);
                close(g_ctx.map_blocked_ips_fd);
                g_ctx.map_blocked_ips_fd = -1;
            }
        }
    }
    
    if (g_ctx.map_blocked_ips_v6_fd >= 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_BLOCKED_IPS_V6);
        if (map) {
            err = bpf_map__reuse_fd(map, g_ctx.map_blocked_ips_v6_fd);
            if (err) {
                LOG("Warning: Failed to reuse blocked_ips_v6 (err=%d), will create new", err);
                close(g_ctx.map_blocked_ips_v6_fd);
                g_ctx.map_blocked_ips_v6_fd = -1;
            }
        }
    }
    
    if (g_ctx.map_whitelist_v4_fd >= 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_WHITELIST_V4);
        if (map) {
            err = bpf_map__reuse_fd(map, g_ctx.map_whitelist_v4_fd);
            if (err) {
                LOG("Warning: Failed to reuse whitelist_v4 (err=%d), will create new", err);
                close(g_ctx.map_whitelist_v4_fd);
                g_ctx.map_whitelist_v4_fd = -1;
            }
        }
    }
    
    if (g_ctx.map_whitelist_v6_fd >= 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_WHITELIST_V6);
        if (map) {
            err = bpf_map__reuse_fd(map, g_ctx.map_whitelist_v6_fd);
            if (err) {
                LOG("Warning: Failed to reuse whitelist_v6 (err=%d), will create new", err);
                close(g_ctx.map_whitelist_v6_fd);
                g_ctx.map_whitelist_v6_fd = -1;
            }
        }
    }
    
    if (g_ctx.map_stats_fd >= 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_STATS);
        if (map) {
            err = bpf_map__reuse_fd(map, g_ctx.map_stats_fd);
            if (err) {
                LOG("Warning: Failed to reuse stats (err=%d), will create new", err);
                close(g_ctx.map_stats_fd);
                g_ctx.map_stats_fd = -1;
            }
        }
    }
    
    // 加载 BPF 程序
    err = bpf_object__load(g_ctx.obj);
    if (err) {
        SET_ERROR("Failed to load BPF object: %s (errno=%d). Try removing old maps: rm -rf %s/*", 
                  strerror(-err), -err, g_ctx.pin_path);
        bpf_object__close(g_ctx.obj);
        g_ctx.obj = NULL;
        return XDP_FW_ERR_LOAD;
    }
    LOG("BPF object loaded successfully");
    
    // 查找程序
    const char *prog_name = opts->prog_name ? opts->prog_name : DEFAULT_PROG_NAME;
    g_ctx.prog = bpf_object__find_program_by_name(g_ctx.obj, prog_name);
    if (!g_ctx.prog) {
        SET_ERROR("Failed to find program '%s'", prog_name);
        bpf_object__close(g_ctx.obj);
        g_ctx.obj = NULL;
        return XDP_FW_ERR_LOAD;
    }
    LOG("Found BPF program: %s", prog_name);
    
    // 获取 Map 文件描述符（如果还没有复用的话）
    if (g_ctx.map_blocked_ips_fd < 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_BLOCKED_IPS);
        if (map) {
            g_ctx.map_blocked_ips_fd = bpf_map__fd(map);
            // Pin 新创建的 map
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_BLOCKED_IPS);
            bpf_map__pin(map, path);
        }
    }
    
    if (g_ctx.map_blocked_ips_v6_fd < 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_BLOCKED_IPS_V6);
        if (map) {
            g_ctx.map_blocked_ips_v6_fd = bpf_map__fd(map);
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_BLOCKED_IPS_V6);
            bpf_map__pin(map, path);
        }
    }
    
    if (g_ctx.map_whitelist_v4_fd < 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_WHITELIST_V4);
        if (map) {
            g_ctx.map_whitelist_v4_fd = bpf_map__fd(map);
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_WHITELIST_V4);
            bpf_map__pin(map, path);
        }
    }
    
    if (g_ctx.map_whitelist_v6_fd < 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_WHITELIST_V6);
        if (map) {
            g_ctx.map_whitelist_v6_fd = bpf_map__fd(map);
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_WHITELIST_V6);
            bpf_map__pin(map, path);
        }
    }
    
    if (g_ctx.map_stats_fd < 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_STATS);
        if (map) {
            g_ctx.map_stats_fd = bpf_map__fd(map);
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_STATS);
            bpf_map__pin(map, path);
        }
    }
    
    if (g_ctx.map_config_fd < 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_CONFIG);
        if (map) {
            g_ctx.map_config_fd = bpf_map__fd(map);
        }
    }
    
    if (g_ctx.map_per_ip_stats_v4_fd < 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_PER_IP_STATS_V4);
        if (map) {
            g_ctx.map_per_ip_stats_v4_fd = bpf_map__fd(map);
        }
    }
    
    if (g_ctx.map_per_ip_stats_v6_fd < 0) {
        map = bpf_object__find_map_by_name(g_ctx.obj, MAP_PER_IP_STATS_V6);
        if (map) {
            g_ctx.map_per_ip_stats_v6_fd = bpf_map__fd(map);
        }
    }
    
    // 验证关键 map
    if (g_ctx.map_blocked_ips_fd < 0) {
        SET_ERROR("Failed to get '%s' map fd", MAP_BLOCKED_IPS);
        bpf_object__close(g_ctx.obj);
        g_ctx.obj = NULL;
        return XDP_FW_ERR_MAP;
    }
    
    LOG("Map FDs: blocked_ips=%d, blocked_ips_v6=%d, whitelist_v4=%d, whitelist_v6=%d, stats=%d, per_ip_v4=%d, per_ip_v6=%d", 
        g_ctx.map_blocked_ips_fd, g_ctx.map_blocked_ips_v6_fd,
        g_ctx.map_whitelist_v4_fd, g_ctx.map_whitelist_v6_fd,
        g_ctx.map_stats_fd, g_ctx.map_per_ip_stats_v4_fd, g_ctx.map_per_ip_stats_v6_fd);
    
    // 附加 XDP 程序
    int prog_fd = bpf_program__fd(g_ctx.prog);
    LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);
    
    // 优先尝试 Native 模式
    if (!opts->force_generic_mode) {
        err = bpf_xdp_attach(g_ctx.ifindex, prog_fd, XDP_FLAGS_DRV_MODE, &attach_opts);
        if (err == 0) {
            g_ctx.xdp_flags = XDP_FLAGS_DRV_MODE;
            LOG("Attached XDP in NATIVE (driver) mode - maximum performance!");
            goto attached;
        }
        LOG("Native mode not supported (%s), trying generic mode...", strerror(-err));
    }
    
    // 回退到 Generic 模式
    err = bpf_xdp_attach(g_ctx.ifindex, prog_fd, XDP_FLAGS_SKB_MODE, &attach_opts);
    if (err) {
        SET_ERROR("Failed to attach XDP program: %s", strerror(-err));
        bpf_object__close(g_ctx.obj);
        g_ctx.obj = NULL;
        return XDP_FW_ERR_ATTACH;
    }
    g_ctx.xdp_flags = XDP_FLAGS_SKB_MODE;
    LOG("Attached XDP in GENERIC (SKB) mode");
    
attached:
    // 初始化 PPS 基准
    g_ctx.pps_baseline.timestamp_ns = get_timestamp_ns();
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_TOTAL, &g_ctx.pps_baseline.total);
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_TCP_SYN, &g_ctx.pps_baseline.syn);
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_DROPPED, &g_ctx.pps_baseline.dropped);
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_PASSED, &g_ctx.pps_baseline.passed);
    
    g_ctx.initialized = 1;
    LOG("XDP Firewall initialized successfully on %s", opts->ifname);
    
    return XDP_FW_OK;
}

// ============================================================================
// 黑名单操作 - IPv4
// ============================================================================

int xdp_fw_ban_ip(uint32_t ip, uint32_t reason) {
    if (!g_ctx.initialized) {
        SET_ERROR("Not initialized");
        return XDP_FW_ERR_INIT;
    }
    
    __u32 key = ip_to_map_key(ip);
    
    struct {
        uint64_t timestamp;
        uint32_t reason;
        uint32_t hit_count;
    } value = {
        .timestamp = get_realtime_ns(),
        .reason = reason,
        .hit_count = 0,
    };
    
    LOG("Banning IP: 0x%08x (key=0x%08x)", ip, key);
    
    int err = bpf_map_update_elem(g_ctx.map_blocked_ips_fd, &key, &value, BPF_ANY);
    if (err) {
        SET_ERROR("Failed to ban IP: %s", strerror(errno));
        if (errno == ENOMEM) return XDP_FW_ERR_NOMEM;
        if (errno == EPERM) return XDP_FW_ERR_PERM;
        return XDP_FW_ERR_MAP;
    }
    
    return XDP_FW_OK;
}

int xdp_fw_unban_ip(uint32_t ip) {
    if (!g_ctx.initialized) {
        SET_ERROR("Not initialized");
        return XDP_FW_ERR_INIT;
    }
    
    __u32 key = ip_to_map_key(ip);
    
    LOG("Unbanning IP: 0x%08x (key=0x%08x)", ip, key);
    
    int err = bpf_map_delete_elem(g_ctx.map_blocked_ips_fd, &key);
    if (err) {
        if (errno == ENOENT) return XDP_FW_ERR_NOENT;
        SET_ERROR("Failed to unban IP: %s", strerror(errno));
        return XDP_FW_ERR_MAP;
    }
    
    return XDP_FW_OK;
}

int xdp_fw_ban_ips_batch(const uint32_t *ips, int count, uint32_t reason) {
    if (!g_ctx.initialized) return 0;
    if (!ips || count <= 0) return 0;
    
    int success = 0;
    for (int i = 0; i < count; i++) {
        if (xdp_fw_ban_ip(ips[i], reason) == XDP_FW_OK) {
            success++;
        }
    }
    
    return success;
}

int xdp_fw_unban_ips_batch(const uint32_t *ips, int count) {
    if (!g_ctx.initialized) return 0;
    if (!ips || count <= 0) return 0;
    
    int success = 0;
    for (int i = 0; i < count; i++) {
        if (xdp_fw_unban_ip(ips[i]) == XDP_FW_OK) {
            success++;
        }
    }
    
    return success;
}

int xdp_fw_is_banned(uint32_t ip, struct xdp_fw_ban_info *info_out) {
    if (!g_ctx.initialized) {
        SET_ERROR("Not initialized");
        return XDP_FW_ERR_INIT;
    }
    
    __u32 key = ip_to_map_key(ip);
    
    struct {
        uint64_t timestamp;
        uint32_t reason;
        uint32_t hit_count;
    } value;
    
    int err = bpf_map_lookup_elem(g_ctx.map_blocked_ips_fd, &key, &value);
    if (err) {
        if (errno == ENOENT) return 0;
        return XDP_FW_ERR_MAP;
    }
    
    if (info_out) {
        info_out->timestamp = value.timestamp;
        info_out->reason = value.reason;
        info_out->hit_count = value.hit_count;
    }
    
    return 1;
}

int xdp_fw_get_banned_ips(uint32_t *out_ips, int max_count) {
    if (!g_ctx.initialized) {
        SET_ERROR("Not initialized");
        return XDP_FW_ERR_INIT;
    }
    
    if (!out_ips || max_count <= 0) {
        SET_ERROR("Invalid parameters");
        return XDP_FW_ERR_INIT;
    }
    
    int count = 0;
    __u32 key = 0, next_key;
    int first = 1;
    
    while (count < max_count) {
        int ret;
        if (first) {
            ret = bpf_map_get_next_key(g_ctx.map_blocked_ips_fd, NULL, &next_key);
            first = 0;
        } else {
            ret = bpf_map_get_next_key(g_ctx.map_blocked_ips_fd, &key, &next_key);
        }
        
        if (ret != 0) break;
        
        out_ips[count] = map_key_to_ip(next_key);
        key = next_key;
        count++;
    }
    
    return count;
}

int xdp_fw_get_banned_count(void) {
    if (!g_ctx.initialized) return 0;
    
    int count = 0;
    __u32 key = 0, next_key;
    
    while (bpf_map_get_next_key(g_ctx.map_blocked_ips_fd, 
                                 count == 0 ? NULL : &key, &next_key) == 0) {
        count++;
        key = next_key;
    }
    
    return count;
}

int xdp_fw_clear_all(void) {
    if (!g_ctx.initialized) return 0;
    
    int count = 0;
    __u32 key, next_key;
    
    while (bpf_map_get_next_key(g_ctx.map_blocked_ips_fd, 
                                 count == 0 ? NULL : &key, &next_key) == 0) {
        bpf_map_delete_elem(g_ctx.map_blocked_ips_fd, &next_key);
        key = next_key;
        count++;
    }
    
    return count;
}

// ============================================================================
// 黑名单操作 - IPv6
// ============================================================================

int xdp_fw_ban_ipv6(const uint8_t ipv6_bytes[16], uint32_t reason) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_blocked_ips_v6_fd < 0) return XDP_FW_ERR_MAP;
    
    struct {
        uint64_t timestamp;
        uint32_t reason;
        uint32_t hit_count;
    } value = {
        .timestamp = get_realtime_ns(),
        .reason = reason,
        .hit_count = 0,
    };
    
    int err = bpf_map_update_elem(g_ctx.map_blocked_ips_v6_fd, ipv6_bytes, &value, BPF_ANY);
    if (err) {
        SET_ERROR("Failed to ban IPv6: %s", strerror(errno));
        return XDP_FW_ERR_MAP;
    }
    
    return XDP_FW_OK;
}

int xdp_fw_unban_ipv6(const uint8_t ipv6_bytes[16]) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_blocked_ips_v6_fd < 0) return XDP_FW_ERR_MAP;
    
    int err = bpf_map_delete_elem(g_ctx.map_blocked_ips_v6_fd, ipv6_bytes);
    if (err && errno != ENOENT) {
        SET_ERROR("Failed to unban IPv6: %s", strerror(errno));
        return XDP_FW_ERR_MAP;
    }
    
    return XDP_FW_OK;
}

int xdp_fw_is_banned_ipv6(const uint8_t ipv6_bytes[16], struct xdp_fw_ban_info *info_out) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_blocked_ips_v6_fd < 0) return XDP_FW_ERR_MAP;
    
    struct {
        uint64_t timestamp;
        uint32_t reason;
        uint32_t hit_count;
    } value;
    
    int err = bpf_map_lookup_elem(g_ctx.map_blocked_ips_v6_fd, ipv6_bytes, &value);
    if (err) {
        if (errno == ENOENT) return 0;
        return XDP_FW_ERR_MAP;
    }
    
    if (info_out) {
        info_out->timestamp = value.timestamp;
        info_out->reason = value.reason;
        info_out->hit_count = value.hit_count;
    }
    
    return 1;
}

int xdp_fw_get_banned_ipv6(uint8_t (*out_ipv6s)[16], int max_count) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_blocked_ips_v6_fd < 0) return XDP_FW_ERR_MAP;
    if (!out_ipv6s || max_count <= 0) return XDP_FW_ERR_INIT;
    
    int count = 0;
    uint8_t key[16] = {0};
    uint8_t next_key[16];
    int first = 1;
    
    while (count < max_count) {
        int ret;
        if (first) {
            ret = bpf_map_get_next_key(g_ctx.map_blocked_ips_v6_fd, NULL, next_key);
            first = 0;
        } else {
            ret = bpf_map_get_next_key(g_ctx.map_blocked_ips_v6_fd, key, next_key);
        }
        
        if (ret != 0) break;
        
        memcpy(out_ipv6s[count], next_key, 16);
        memcpy(key, next_key, 16);
        count++;
    }
    
    return count;
}

int xdp_fw_get_banned_count_v6(void) {
    if (!g_ctx.initialized) return 0;
    if (g_ctx.map_blocked_ips_v6_fd < 0) return 0;
    
    int count = 0;
    uint8_t key[16] = {0};
    uint8_t next_key[16];
    
    if (bpf_map_get_next_key(g_ctx.map_blocked_ips_v6_fd, NULL, next_key) != 0) {
        return 0;
    }
    
    count = 1;
    memcpy(key, next_key, 16);
    
    while (bpf_map_get_next_key(g_ctx.map_blocked_ips_v6_fd, key, next_key) == 0) {
        count++;
        memcpy(key, next_key, 16);
    }
    
    return count;
}

int xdp_fw_clear_all_v6(void) {
    if (!g_ctx.initialized) return 0;
    if (g_ctx.map_blocked_ips_v6_fd < 0) return 0;
    
    int count = 0;
    uint8_t key[16];
    uint8_t next_key[16];
    
    while (bpf_map_get_next_key(g_ctx.map_blocked_ips_v6_fd, 
                                 count == 0 ? NULL : key, next_key) == 0) {
        bpf_map_delete_elem(g_ctx.map_blocked_ips_v6_fd, next_key);
        memcpy(key, next_key, 16);
        count++;
    }
    
    return count;
}

// ============================================================================
// 白名单操作 - IPv4
// ============================================================================

int xdp_fw_whitelist_add(uint32_t ip, uint32_t prefixlen) {
    if (!g_ctx.initialized) {
        SET_ERROR("Not initialized");
        return XDP_FW_ERR_INIT;
    }
    
    if (g_ctx.map_whitelist_v4_fd < 0) {
        SET_ERROR("Whitelist map not available");
        return XDP_FW_ERR_MAP;
    }
    
    if (prefixlen == 0 || prefixlen > 32) {
        SET_ERROR("Invalid prefixlen: %u (must be 1-32)", prefixlen);
        return XDP_FW_ERR_INIT;
    }
    
    struct ipv4_lpm_key key = {
        .prefixlen = prefixlen,
        .addr = ip_to_map_key(ip),
    };
    __u8 value = 1;
    
    LOG("Adding to whitelist: 0x%08x/%u", ip, prefixlen);
    
    int err = bpf_map_update_elem(g_ctx.map_whitelist_v4_fd, &key, &value, BPF_ANY);
    if (err) {
        SET_ERROR("Failed to add to whitelist: %s", strerror(errno));
        if (errno == ENOMEM) return XDP_FW_ERR_NOMEM;
        return XDP_FW_ERR_MAP;
    }
    
    return XDP_FW_OK;
}

int xdp_fw_whitelist_remove(uint32_t ip, uint32_t prefixlen) {
    if (!g_ctx.initialized) {
        SET_ERROR("Not initialized");
        return XDP_FW_ERR_INIT;
    }
    
    if (g_ctx.map_whitelist_v4_fd < 0) {
        SET_ERROR("Whitelist map not available");
        return XDP_FW_ERR_MAP;
    }
    
    if (prefixlen == 0 || prefixlen > 32) {
        SET_ERROR("Invalid prefixlen: %u", prefixlen);
        return XDP_FW_ERR_INIT;
    }
    
    struct ipv4_lpm_key key = {
        .prefixlen = prefixlen,
        .addr = ip_to_map_key(ip),
    };
    
    LOG("Removing from whitelist: 0x%08x/%u", ip, prefixlen);
    
    int err = bpf_map_delete_elem(g_ctx.map_whitelist_v4_fd, &key);
    if (err) {
        if (errno == ENOENT) return XDP_FW_ERR_NOENT;
        SET_ERROR("Failed to remove from whitelist: %s", strerror(errno));
        return XDP_FW_ERR_MAP;
    }
    
    return XDP_FW_OK;
}

int xdp_fw_whitelist_check(uint32_t ip) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_whitelist_v4_fd < 0) return XDP_FW_ERR_MAP;
    
    // 使用 prefixlen=32 进行 LPM 查找
    // LPM Trie 会自动匹配最长前缀
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .addr = ip_to_map_key(ip),
    };
    
    __u8 value;
    int err = bpf_map_lookup_elem(g_ctx.map_whitelist_v4_fd, &key, &value);
    if (err) {
        if (errno == ENOENT) return 0;
        return XDP_FW_ERR_MAP;
    }
    
    return 1;
}

int xdp_fw_whitelist_count(void) {
    if (!g_ctx.initialized) return 0;
    if (g_ctx.map_whitelist_v4_fd < 0) return 0;
    
    int count = 0;
    struct ipv4_lpm_key key = {0}, next_key;
    
    // LPM Trie 的遍历
    while (bpf_map_get_next_key(g_ctx.map_whitelist_v4_fd, 
                                 count == 0 ? NULL : &key, &next_key) == 0) {
        count++;
        key = next_key;
    }
    
    return count;
}

int xdp_fw_whitelist_clear(void) {
    if (!g_ctx.initialized) return 0;
    if (g_ctx.map_whitelist_v4_fd < 0) return 0;
    
    int count = 0;
    struct ipv4_lpm_key key, next_key;
    
    while (bpf_map_get_next_key(g_ctx.map_whitelist_v4_fd, 
                                 count == 0 ? NULL : &key, &next_key) == 0) {
        bpf_map_delete_elem(g_ctx.map_whitelist_v4_fd, &next_key);
        key = next_key;
        count++;
    }
    
    LOG("Cleared %d whitelist entries", count);
    return count;
}

// ============================================================================
// 白名单操作 - IPv6
// ============================================================================

int xdp_fw_whitelist_add_v6(const uint8_t ipv6_bytes[16], uint32_t prefixlen) {
    if (!g_ctx.initialized) {
        SET_ERROR("Not initialized");
        return XDP_FW_ERR_INIT;
    }
    
    if (g_ctx.map_whitelist_v6_fd < 0) {
        SET_ERROR("IPv6 whitelist map not available");
        return XDP_FW_ERR_MAP;
    }
    
    if (prefixlen == 0 || prefixlen > 128) {
        SET_ERROR("Invalid prefixlen: %u (must be 1-128)", prefixlen);
        return XDP_FW_ERR_INIT;
    }
    
    struct ipv6_lpm_key key = {
        .prefixlen = prefixlen,
    };
    memcpy(key.addr, ipv6_bytes, 16);
    __u8 value = 1;
    
    int err = bpf_map_update_elem(g_ctx.map_whitelist_v6_fd, &key, &value, BPF_ANY);
    if (err) {
        SET_ERROR("Failed to add IPv6 to whitelist: %s", strerror(errno));
        return XDP_FW_ERR_MAP;
    }
    
    return XDP_FW_OK;
}

int xdp_fw_whitelist_remove_v6(const uint8_t ipv6_bytes[16], uint32_t prefixlen) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_whitelist_v6_fd < 0) return XDP_FW_ERR_MAP;
    
    if (prefixlen == 0 || prefixlen > 128) return XDP_FW_ERR_INIT;
    
    struct ipv6_lpm_key key = {
        .prefixlen = prefixlen,
    };
    memcpy(key.addr, ipv6_bytes, 16);
    
    int err = bpf_map_delete_elem(g_ctx.map_whitelist_v6_fd, &key);
    if (err && errno != ENOENT) {
        return XDP_FW_ERR_MAP;
    }
    
    return XDP_FW_OK;
}

int xdp_fw_whitelist_check_v6(const uint8_t ipv6_bytes[16]) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_whitelist_v6_fd < 0) return XDP_FW_ERR_MAP;
    
    struct ipv6_lpm_key key = {
        .prefixlen = 128,
    };
    memcpy(key.addr, ipv6_bytes, 16);
    
    __u8 value;
    int err = bpf_map_lookup_elem(g_ctx.map_whitelist_v6_fd, &key, &value);
    if (err) {
        if (errno == ENOENT) return 0;
        return XDP_FW_ERR_MAP;
    }
    
    return 1;
}

int xdp_fw_whitelist_count_v6(void) {
    if (!g_ctx.initialized) return 0;
    if (g_ctx.map_whitelist_v6_fd < 0) return 0;
    
    int count = 0;
    struct ipv6_lpm_key key = {0}, next_key;
    
    while (bpf_map_get_next_key(g_ctx.map_whitelist_v6_fd, 
                                 count == 0 ? NULL : &key, &next_key) == 0) {
        count++;
        key = next_key;
    }
    
    return count;
}

int xdp_fw_whitelist_clear_v6(void) {
    if (!g_ctx.initialized) return 0;
    if (g_ctx.map_whitelist_v6_fd < 0) return 0;
    
    int count = 0;
    struct ipv6_lpm_key key, next_key;
    
    while (bpf_map_get_next_key(g_ctx.map_whitelist_v6_fd, 
                                 count == 0 ? NULL : &key, &next_key) == 0) {
        bpf_map_delete_elem(g_ctx.map_whitelist_v6_fd, &next_key);
        key = next_key;
        count++;
    }
    
    return count;
}

// ============================================================================
// 统计与监控
// ============================================================================

int xdp_fw_get_stats(struct xdp_fw_stats *stats_out) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (!stats_out) return XDP_FW_ERR_INIT;
    
    memset(stats_out, 0, sizeof(*stats_out));
    
    if (g_ctx.map_stats_fd >= 0) {
        int num_cpus = libbpf_num_possible_cpus();
        if (num_cpus < 0) num_cpus = 1;
        
        uint64_t *values = calloc(num_cpus, sizeof(uint64_t));
        if (values) {
            uint32_t key;
            
            // STATS_PASSED
            key = STATS_PASSED;
            if (bpf_map_lookup_elem(g_ctx.map_stats_fd, &key, values) == 0) {
                for (int i = 0; i < num_cpus; i++) {
                    stats_out->packets_passed += values[i];
                }
            }
            
            // STATS_DROPPED
            key = STATS_DROPPED;
            memset(values, 0, num_cpus * sizeof(uint64_t));
            if (bpf_map_lookup_elem(g_ctx.map_stats_fd, &key, values) == 0) {
                for (int i = 0; i < num_cpus; i++) {
                    stats_out->packets_dropped += values[i];
                }
            }
            
            // STATS_TOTAL
            key = STATS_TOTAL;
            memset(values, 0, num_cpus * sizeof(uint64_t));
            if (bpf_map_lookup_elem(g_ctx.map_stats_fd, &key, values) == 0) {
                for (int i = 0; i < num_cpus; i++) {
                    stats_out->packets_total += values[i];
                }
            }
            
            // STATS_TCP_SYN
            key = STATS_TCP_SYN;
            memset(values, 0, num_cpus * sizeof(uint64_t));
            if (bpf_map_lookup_elem(g_ctx.map_stats_fd, &key, values) == 0) {
                for (int i = 0; i < num_cpus; i++) {
                    stats_out->packets_syn += values[i];
                }
            }
            
            // STATS_WHITELISTED
            key = STATS_WHITELISTED;
            memset(values, 0, num_cpus * sizeof(uint64_t));
            if (bpf_map_lookup_elem(g_ctx.map_stats_fd, &key, values) == 0) {
                for (int i = 0; i < num_cpus; i++) {
                    stats_out->packets_whitelisted += values[i];
                }
            }
            
            free(values);
        }
    }
    
    // 统计封禁和白名单数量
    stats_out->banned_ips_count = xdp_fw_get_banned_count();
    stats_out->banned_ips_v6_count = xdp_fw_get_banned_count_v6();
    stats_out->whitelist_count = xdp_fw_whitelist_count();
    stats_out->whitelist_v6_count = xdp_fw_whitelist_count_v6();
    
    return XDP_FW_OK;
}

int xdp_fw_get_pps(struct xdp_fw_pps_stats *stats_out) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (!stats_out) return XDP_FW_ERR_INIT;
    
    memset(stats_out, 0, sizeof(*stats_out));
    
    // 获取当前时间和统计值
    uint64_t now = get_timestamp_ns();
    uint64_t total = 0, syn = 0, dropped = 0, passed = 0;
    
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_TOTAL, &total);
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_TCP_SYN, &syn);
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_DROPPED, &dropped);
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_PASSED, &passed);
    
    // 计算时间间隔（纳秒）
    uint64_t interval_ns = now - g_ctx.pps_baseline.timestamp_ns;
    
    // 避免除以零
    if (interval_ns > 0) {
        // 计算差值
        uint64_t delta_total = total - g_ctx.pps_baseline.total;
        uint64_t delta_syn = syn - g_ctx.pps_baseline.syn;
        uint64_t delta_dropped = dropped - g_ctx.pps_baseline.dropped;
        uint64_t delta_passed = passed - g_ctx.pps_baseline.passed;
        
        // 转换为每秒（PPS = 差值 * 1e9 / 间隔纳秒）
        stats_out->pps = (delta_total * 1000000000ULL) / interval_ns;
        stats_out->syn_pps = (delta_syn * 1000000000ULL) / interval_ns;
        stats_out->dropped_pps = (delta_dropped * 1000000000ULL) / interval_ns;
        stats_out->passed_pps = (delta_passed * 1000000000ULL) / interval_ns;
        stats_out->interval_ns = interval_ns;
    }
    
    stats_out->timestamp_ns = now;
    
    // 更新基准值
    g_ctx.pps_baseline.total = total;
    g_ctx.pps_baseline.syn = syn;
    g_ctx.pps_baseline.dropped = dropped;
    g_ctx.pps_baseline.passed = passed;
    g_ctx.pps_baseline.timestamp_ns = now;
    
    return XDP_FW_OK;
}

void xdp_fw_reset_pps_baseline(void) {
    if (!g_ctx.initialized) return;
    
    g_ctx.pps_baseline.timestamp_ns = get_timestamp_ns();
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_TOTAL, &g_ctx.pps_baseline.total);
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_TCP_SYN, &g_ctx.pps_baseline.syn);
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_DROPPED, &g_ctx.pps_baseline.dropped);
    get_percpu_stats_sum(g_ctx.map_stats_fd, STATS_PASSED, &g_ctx.pps_baseline.passed);
}

int xdp_fw_reset_stats(void) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_stats_fd < 0) return XDP_FW_OK;
    
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) num_cpus = 1;
    
    uint64_t *zeros = calloc(num_cpus, sizeof(uint64_t));
    if (zeros) {
        for (uint32_t key = 0; key < STATS_MAX; key++) {
            bpf_map_update_elem(g_ctx.map_stats_fd, &key, zeros, BPF_ANY);
        }
        free(zeros);
    }
    
    // 重置 PPS 基准
    xdp_fw_reset_pps_baseline();
    
    return XDP_FW_OK;
}

// ============================================================================
// Per-IP 统计 API 实现
// ============================================================================

int xdp_fw_get_all_ip_stats_v4(struct xdp_fw_ip_stats_entry *entries_out, int max_count) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_per_ip_stats_v4_fd < 0) return XDP_FW_ERR_MAP;
    if (!entries_out || max_count <= 0) return XDP_FW_ERR_INIT;
    
    int count = 0;
    __u32 key = 0, next_key;
    struct per_ip_stats value;
    
    int first = 1;
    while (count < max_count) {
        int ret;
        if (first) {
            ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v4_fd, NULL, &next_key);
            first = 0;
        } else {
            ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v4_fd, &key, &next_key);
        }
        
        if (ret != 0) break;
        
        if (bpf_map_lookup_elem(g_ctx.map_per_ip_stats_v4_fd, &next_key, &value) == 0) {
            entries_out[count].ip = map_key_to_ip(next_key);
            entries_out[count].stats.packets = value.packets;
            entries_out[count].stats.syn_packets = value.syn_packets;
            count++;
        }
        
        key = next_key;
    }
    
    return count;
}

int xdp_fw_get_all_ip_stats_v6(struct xdp_fw_ip6_stats_entry *entries_out, int max_count) {
    if (!g_ctx.initialized) return XDP_FW_ERR_INIT;
    if (g_ctx.map_per_ip_stats_v6_fd < 0) return XDP_FW_ERR_MAP;
    if (!entries_out || max_count <= 0) return XDP_FW_ERR_INIT;
    
    int count = 0;
    uint8_t key[16] = {0}, next_key[16];
    struct per_ip_stats value;
    
    int first = 1;
    while (count < max_count) {
        int ret;
        if (first) {
            ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v6_fd, NULL, next_key);
            first = 0;
        } else {
            ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v6_fd, key, next_key);
        }
        
        if (ret != 0) break;
        
        if (bpf_map_lookup_elem(g_ctx.map_per_ip_stats_v6_fd, next_key, &value) == 0) {
            memcpy(entries_out[count].ip, next_key, 16);
            entries_out[count].stats.packets = value.packets;
            entries_out[count].stats.syn_packets = value.syn_packets;
            count++;
        }
        
        memcpy(key, next_key, 16);
    }
    
    return count;
}

int xdp_fw_clear_per_ip_stats(void) {
    if (!g_ctx.initialized) return 0;
    
    int count = 0;
    
    // 清除 IPv4
    if (g_ctx.map_per_ip_stats_v4_fd >= 0) {
        __u32 key = 0, next_key;
        int first = 1;
        while (1) {
            int ret;
            if (first) {
                ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v4_fd, NULL, &next_key);
                first = 0;
            } else {
                ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v4_fd, &key, &next_key);
            }
            if (ret != 0) break;
            
            bpf_map_delete_elem(g_ctx.map_per_ip_stats_v4_fd, &next_key);
            key = next_key;
            count++;
        }
    }
    
    // 清除 IPv6
    if (g_ctx.map_per_ip_stats_v6_fd >= 0) {
        uint8_t key[16], next_key[16];
        int first = 1;
        while (1) {
            int ret;
            if (first) {
                ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v6_fd, NULL, next_key);
                first = 0;
            } else {
                ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v6_fd, key, next_key);
            }
            if (ret != 0) break;
            
            bpf_map_delete_elem(g_ctx.map_per_ip_stats_v6_fd, next_key);
            memcpy(key, next_key, 16);
            count++;
        }
    }
    
    LOG("Cleared %d per-IP stats entries", count);
    return count;
}

int xdp_fw_get_per_ip_stats_count(void) {
    if (!g_ctx.initialized) return 0;
    
    int count = 0;
    
    // 统计 IPv4
    if (g_ctx.map_per_ip_stats_v4_fd >= 0) {
        __u32 key = 0, next_key;
        int first = 1;
        while (1) {
            int ret;
            if (first) {
                ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v4_fd, NULL, &next_key);
                first = 0;
            } else {
                ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v4_fd, &key, &next_key);
            }
            if (ret != 0) break;
            key = next_key;
            count++;
        }
    }
    
    // 统计 IPv6
    if (g_ctx.map_per_ip_stats_v6_fd >= 0) {
        uint8_t key[16], next_key[16];
        int first = 1;
        while (1) {
            int ret;
            if (first) {
                ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v6_fd, NULL, next_key);
                first = 0;
            } else {
                ret = bpf_map_get_next_key(g_ctx.map_per_ip_stats_v6_fd, key, next_key);
            }
            if (ret != 0) break;
            memcpy(key, next_key, 16);
            count++;
        }
    }
    
    return count;
}

// ============================================================================
// 工具函数
// ============================================================================

int xdp_fw_check_permissions(void) {
    if (geteuid() == 0) {
        return 1;
    }
    
    cap_t caps = cap_get_proc();
    if (caps == NULL) {
        return 0;
    }
    
    cap_flag_value_t cap_bpf_val, cap_net_admin_val;
    
    if (cap_get_flag(caps, CAP_BPF, CAP_EFFECTIVE, &cap_bpf_val) != 0) {
        cap_free(caps);
        return 0;
    }
    
    if (cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &cap_net_admin_val) != 0) {
        cap_free(caps);
        return 0;
    }
    
    cap_free(caps);
    
    return (cap_bpf_val == CAP_SET && cap_net_admin_val == CAP_SET) ? 1 : 0;
}

const char* xdp_fw_get_last_error(void) {
    return g_ctx.error_buf;
}

const char* xdp_fw_strerror(int err) {
    switch (err) {
        case XDP_FW_OK:         return "Success";
        case XDP_FW_ERR_PERM:   return "Permission denied";
        case XDP_FW_ERR_NODEV:  return "Network interface not found";
        case XDP_FW_ERR_LOAD:   return "Failed to load BPF program";
        case XDP_FW_ERR_ATTACH: return "Failed to attach XDP program";
        case XDP_FW_ERR_MAP:    return "BPF map operation failed";
        case XDP_FW_ERR_INIT:   return "Not initialized";
        case XDP_FW_ERR_ALREADY:return "Already initialized";
        case XDP_FW_ERR_NOMEM:  return "Out of memory";
        case XDP_FW_ERR_NOENT:  return "Entry not found";
        default:                return "Unknown error";
    }
}

const char* xdp_fw_version(void) {
    return VERSION;
}

int xdp_fw_ip_from_string(const char *ip_str, uint32_t *ip_out) {
    if (!ip_str || !ip_out) return -1;
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }
    
    // inet_pton 返回网络字节序，转换为主机字节序
    *ip_out = ntohl(addr.s_addr);
    return 0;
}

char* xdp_fw_ip_to_string(uint32_t ip, char *buf, int buf_len) {
    if (!buf || buf_len < 16) return NULL;
    
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    
    if (inet_ntop(AF_INET, &addr, buf, buf_len) == NULL) {
        return NULL;
    }
    
    return buf;
}

int xdp_fw_is_initialized(void) {
    return g_ctx.initialized;
}

// ============================================================================
// 关闭与销毁
// ============================================================================

void xdp_fw_close(void) {
    if (!g_ctx.initialized) return;
    
    LOG("Closing XDP Firewall...");
    
    // 分离 XDP 程序
    if (g_ctx.ifindex > 0) {
        bpf_xdp_detach(g_ctx.ifindex, g_ctx.xdp_flags, NULL);
        LOG("Detached XDP from %s", g_ctx.ifname);
    }
    
    // 关闭 BPF 对象（保留 pinned maps）
    if (g_ctx.obj) {
        bpf_object__close(g_ctx.obj);
        g_ctx.obj = NULL;
    }
    
    // 重置状态
    g_ctx.initialized = 0;
    g_ctx.prog = NULL;
    g_ctx.link = NULL;
    g_ctx.ifindex = 0;
    
    // 重置 map fd（不关闭，因为可能是 pinned 的）
    g_ctx.map_blocked_ips_fd = -1;
    g_ctx.map_blocked_ips_v6_fd = -1;
    g_ctx.map_whitelist_v4_fd = -1;
    g_ctx.map_whitelist_v6_fd = -1;
    g_ctx.map_stats_fd = -1;
    g_ctx.map_config_fd = -1;
    g_ctx.map_per_ip_stats_v4_fd = -1;
    g_ctx.map_per_ip_stats_v6_fd = -1;
    
    LOG("XDP Firewall closed (pinned maps preserved)");
}

void xdp_fw_destroy(void) {
    xdp_fw_close();
    
    // 删除 pinned maps
    char path[512];
    
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_BLOCKED_IPS);
    unlink(path);
    
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_BLOCKED_IPS_V6);
    unlink(path);
    
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_WHITELIST_V4);
    unlink(path);
    
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_WHITELIST_V6);
    unlink(path);
    
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_STATS);
    unlink(path);
    
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_CONFIG);
    unlink(path);
    
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_PER_IP_STATS_V4);
    unlink(path);
    
    snprintf(path, sizeof(path), "%s/%s", g_ctx.pin_path, MAP_PER_IP_STATS_V6);
    unlink(path);
    
    rmdir(g_ctx.pin_path);
    
    LOG("XDP Firewall destroyed (pinned maps removed)");
}