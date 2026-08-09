// SPDX-License-Identifier: GPL-2.0
// XDP Firewall - 高性能恶意 IP 拦截器（增强版 v1.1）
// Author: LmyzMail Team
// 
// 此程序运行在内核态，直接在网卡驱动层拦截恶意 IP 的数据包
// 性能可达每秒数百万包，远超 iptables
// 
// v1.1 修复：
//   - 移除所有 map 定义中的 LIBBPF_PIN_BY_NAME（改由用户态代码管理）
//   - 避免与用户态 pinning 路径冲突
//
// v1.1 新增功能：
//   - XDP 层白名单（内置内网网段 + 动态 CIDR）
//   - PPS 和 SYN PPS 统计
//   - Per-IP 统计（用于单IP PPS检测）

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ============================================================================
// 常量定义
// ============================================================================

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

// BPF Map 标志（如果未定义则手动定义）
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

#ifndef BPF_ANY
#define BPF_ANY         0
#endif

#ifndef BPF_NOEXIST
#define BPF_NOEXIST     1
#endif

#ifndef BPF_EXIST
#define BPF_EXIST       2
#endif

// 统计索引
#define STATS_PASSED        0   // 放行的包
#define STATS_DROPPED       1   // 黑名单丢弃的包
#define STATS_TOTAL         2   // 总包数（用于计算 PPS）
#define STATS_TCP_SYN       3   // TCP SYN 包数（用于计算 SYN PPS）
#define STATS_WHITELISTED   4   // 白名单放行的包
#define STATS_MAX           8   // 统计数组大小

// Map 最大条目数
#define MAX_BLOCKED_IPS     100000  // 可支持 10 万个封禁 IP
#define MAX_WHITELIST_IPS   10000   // 白名单 IP/CIDR

// ============================================================================
// 数据结构定义
// ============================================================================

// 封禁元数据
struct ban_info {
    __u64 timestamp;    // 封禁时间戳（纳秒）
    __u32 reason;       // 封禁原因代码
    __u32 hit_count;    // 命中次数
};

// IPv4 LPM Key（用于 CIDR 匹配）
struct ipv4_lpm_key {
    __u32 prefixlen;    // 前缀长度（0-32）
    __u32 addr;         // IPv4 地址（网络字节序）
};

// IPv6 LPM Key
struct ipv6_lpm_key {
    __u32 prefixlen;    // 前缀长度（0-128）
    __u8 addr[16];      // IPv6 地址（网络字节序）
};

// 配置结构
struct config {
    __u32 enabled;           // 是否启用过滤
    __u32 log_dropped;       // 是否记录丢弃的包
    __u32 whitelist_only;    // 仅白名单模式（丢弃所有非白名单）
    __u32 reserved;          // 保留
};

// Per-IP 统计结构（用于单IP PPS检测）
struct per_ip_stats {
    __u64 packets;        // 总包数
    __u64 syn_packets;    // SYN包数
};

// ============================================================================
// BPF Maps 定义
// ============================================================================

// 主黑名单 Map：存储被封禁的 IPv4 地址
// Key: IPv4 地址（网络字节序，Big Endian）
// Value: 封禁元数据
// 修复：移除 LIBBPF_PIN_BY_NAME，改由用户态代码管理 pinning
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __u32);              // IPv4，网络字节序
    __type(value, struct ban_info);
} blocked_ips SEC(".maps");

// IPv6 黑名单
// 修复：移除 LIBBPF_PIN_BY_NAME
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, struct in6_addr);    // IPv6 地址
    __type(value, struct ban_info);
} blocked_ips_v6 SEC(".maps");

// IPv4 白名单（LPM Trie，支持 CIDR）
// 例如：192.168.0.0/16 可以匹配整个网段
// 修复：移除 LIBBPF_PIN_BY_NAME
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_WHITELIST_IPS);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);             // 1 = whitelisted
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_v4 SEC(".maps");

// IPv6 白名单（LPM Trie）
// 修复：移除 LIBBPF_PIN_BY_NAME
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_WHITELIST_IPS);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_v6 SEC(".maps");

// 统计计数器（Per-CPU 避免锁竞争）
// 修复：移除 LIBBPF_PIN_BY_NAME
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// 配置 Map
// 修复：移除 LIBBPF_PIN_BY_NAME（可选，config 通常不需要 pin）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// Per-IP 统计 Map - IPv4 (LRU自动淘汰低活跃IP)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, __u32);
    __type(value, struct per_ip_stats);
} per_ip_stats_v4 SEC(".maps");

// Per-IP 统计 Map - IPv6
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, struct in6_addr);
    __type(value, struct per_ip_stats);
} per_ip_stats_v6 SEC(".maps");

// ============================================================================
// 辅助函数：统计更新
// ============================================================================

/**
 * 更新统计计数器（原子操作）
 * 
 * @param key 统计项目的键（STATS_PASSED 等）
 * 
 * 该函数通过原子增加操作更新 Per-CPU 统计数组中的对应计数器
 * 避免了锁竞争，性能最优
 */
static __always_inline void update_stats(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

// ============================================================================
// 辅助函数：Per-IP 统计更新
// ============================================================================

/**
 * 更新 IPv4 的 per-IP 统计
 */
static __always_inline void update_per_ip_stats_v4(__u32 src_ip, int is_syn) {
    struct per_ip_stats *stats = bpf_map_lookup_elem(&per_ip_stats_v4, &src_ip);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        if (is_syn) {
            __sync_fetch_and_add(&stats->syn_packets, 1);
        }
    } else {
        struct per_ip_stats new_stats = {
            .packets = 1,
            .syn_packets = is_syn ? 1 : 0,
        };
        bpf_map_update_elem(&per_ip_stats_v4, &src_ip, &new_stats, BPF_NOEXIST);
    }
}

/**
 * 更新 IPv6 的 per-IP 统计
 */
static __always_inline void update_per_ip_stats_v6(const __u8 addr[16], int is_syn) {
    struct in6_addr key;
    __builtin_memcpy(&key, addr, 16);
    
    struct per_ip_stats *stats = bpf_map_lookup_elem(&per_ip_stats_v6, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        if (is_syn) {
            __sync_fetch_and_add(&stats->syn_packets, 1);
        }
    } else {
        struct per_ip_stats new_stats = {
            .packets = 1,
            .syn_packets = is_syn ? 1 : 0,
        };
        bpf_map_update_elem(&per_ip_stats_v6, &key, &new_stats, BPF_NOEXIST);
    }
}

// ============================================================================
// 辅助函数：内置白名单检查（硬编码，最高性能）
// ============================================================================

/**
 * 检查是否是内网/本机 IPv4 地址
 * 这些地址永远不应被封禁
 * 
 * 支持的保留范围：
 *  - 127.0.0.0/8 (loopback)
 *  - 10.0.0.0/8 (Private Class A)
 *  - 172.16.0.0/12 (Private Class B)
 *  - 192.168.0.0/16 (Private Class C)
 *  - 169.254.0.0/16 (Link-local)
 *  - 0.0.0.0/8 (当前网络)
 *  - 224.0.0.0/4 (组播地址)
 *  - 255.255.255.255 (广播)
 * 
 * @param ip IPv4 地址（网络字节序）
 * @return 1 = 是内网地址，0 = 不是
 */
static __always_inline int is_builtin_whitelist_v4(__u32 ip) {
    // 网络字节序：第一个字节是最高位
    // 例如 192.168.1.1 在网络字节序中存储为 0xC0A80101
    // 提取字节时：b0 = 0xC0 (192), b1 = 0xA8 (168), 等等
    __u8 b0 = ip & 0xFF;          // 第一个字节
    __u8 b1 = (ip >> 8) & 0xFF;   // 第二个字节
    
    // 127.0.0.0/8 (loopback)
    // 任何 127.x.x.x 的地址都是本地回环
    if (b0 == 127)
        return 1;
    
    // 10.0.0.0/8 (Private Class A)
    // 任何 10.x.x.x 的地址都是私有地址
    if (b0 == 10)
        return 1;
    
    // 172.16.0.0/12 (Private Class B: 172.16.x.x - 172.31.x.x)
    // 第一个字节是 172，第二个字节在 16-31 之间
    if (b0 == 172 && (b1 >= 16 && b1 <= 31))
        return 1;
    
    // 192.168.0.0/16 (Private Class C)
    // 192.168.x.x 的地址都是私有地址
    if (b0 == 192 && b1 == 168)
        return 1;
    
    // 169.254.0.0/16 (Link-local)
    // 169.254.x.x 用于本地链路自动配置
    if (b0 == 169 && b1 == 254)
        return 1;
    
    // 0.0.0.0/8 (当前网络)
    // 0.x.x.x 不应该在互联网上出现
    if (b0 == 0)
        return 1;
    
    // 224.0.0.0/4 (组播地址 224-239)
    // 组播地址范围从 224 到 239
    if (b0 >= 224 && b0 <= 239)
        return 1;
    
    // 255.255.255.255 (广播)
    // 全 1 的地址是广播地址
    if (ip == 0xFFFFFFFF)
        return 1;
    
    return 0;
}

/**
 * 检查是否是内网/本机 IPv6 地址
 * 
 * 支持的保留范围：
 *  - ::1/128 (loopback)
 *  - ::/128 (未指定地址)
 *  - fe80::/10 (Link-local)
 *  - fc00::/7 (Unique Local Address, ULA)
 *  - ff00::/8 (组播)
 *  - ::ffff:0:0/96 (IPv4-mapped IPv6)
 * 
 * @param addr IPv6 地址（16字节数组）
 * @return 1 = 是内网地址，0 = 不是
 */
static __always_inline int is_builtin_whitelist_v6(const __u8 addr[16]) {
    // 使用指针转换访问不同粒度的数据
    // IPv6 地址是 128 位，可以分解为：
    // - 4 个 32 位字 (addr32)
    // - 8 个 16 位字 (addr16)
    const __u32 *addr32 = (const __u32 *)addr;
    const __u16 *addr16 = (const __u16 *)addr;
    
    __u8 b0 = addr[0];
    __u8 b1 = addr[1];
    
    // ::1 (loopback)
    // IPv6 回环地址：前 128-8=120 位为 0，最后 8 位为 1
    // 表示为：0:0:0:0:0:0:0:1
    if (addr32[0] == 0 &&
        addr32[1] == 0 &&
        addr32[2] == 0 &&
        addr32[3] == bpf_htonl(1)) {
        return 1;
    }
    
    // :: (未指定地址)
    // 全 0 地址，表示"未指定"
    if (addr32[0] == 0 &&
        addr32[1] == 0 &&
        addr32[2] == 0 &&
        addr32[3] == 0) {
        return 1;
    }
    
    // fe80::/10 (Link-local)
    // 第一个字节是 0xfe，第二个字节高 2 位是 10
    if (b0 == 0xfe && (b1 & 0xc0) == 0x80)
        return 1;
    
    // fc00::/7 (Unique Local Address, ULA)
    // 第一个字节高 1 位是 1，即 1111110x
    if ((b0 & 0xfe) == 0xfc)
        return 1;
    
    // ff00::/8 (组播)
    // 第一个字节是 0xff
    if (b0 == 0xff)
        return 1;
    
    // ::ffff:0:0/96 (IPv4-mapped IPv6)
    // IPv4 映射的 IPv6 地址格式：0:0:0:0:0:ffff:IPv4
    // 检查前三个 32 位字和第四个 16 位字
    if (addr32[0] == 0 &&
        addr32[1] == 0 &&
        addr16[4] == 0 &&
        addr16[5] == bpf_htons(0xFFFF)) {
        // 检查映射的 IPv4 是否是内网
        __u32 ipv4 = addr32[3];
        return is_builtin_whitelist_v4(ipv4);
    }
    
    return 0;
}

// ============================================================================
// 辅助函数：动态白名单检查（LPM Trie）
// ============================================================================

/**
 * 检查 IPv4 是否在动态白名单中
 * 使用 LPM Trie，支持 CIDR 前缀匹配
 * 
 * @param ip IPv4 地址（网络字节序）
 * @return 非零表示在白名单中
 */
static __always_inline int check_dynamic_whitelist_v4(__u32 ip) {
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .addr = ip,
    };
    return bpf_map_lookup_elem(&whitelist_v4, &key) != NULL;
}

/**
 * 检查 IPv6 是否在动态白名单中
 * 使用 LPM Trie，支持 CIDR 前缀匹配
 * 
 * @param addr IPv6 地址（16字节）
 * @return 非零表示在白名单中
 */
static __always_inline int check_dynamic_whitelist_v6(const __u8 addr[16]) {
    struct ipv6_lpm_key key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(key.addr, addr, 16);
    return bpf_map_lookup_elem(&whitelist_v6, &key) != NULL;
}

// ============================================================================
// 辅助函数：黑名单检查
// ============================================================================

/**
 * 检查 IPv4 是否在黑名单中
 * 同时原子增加命中计数
 * 
 * @param src_ip IPv4 源地址（网络字节序）
 * @return 1 = 被封禁，0 = 未被封禁
 */
static __always_inline int check_ipv4_blocked(__u32 src_ip) {
    struct ban_info *info = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (info) {
        // 原子增加命中计数
        __sync_fetch_and_add(&info->hit_count, 1);
        return 1;
    }
    return 0;
}

/**
 * 检查 IPv6 是否在黑名单中
 * 同时原子增加命中计数
 * 
 * @param addr IPv6 地址（16字节）
 * @return 1 = 被封禁，0 = 未被封禁
 */
static __always_inline int check_ipv6_blocked(const __u8 addr[16]) {
    // 复制到本地变量以避免对齐问题
    // BPF 中直接访问指针可能会导致对齐不匹配的错误
    struct in6_addr key;
    __builtin_memcpy(&key, addr, 16);
    
    struct ban_info *info = bpf_map_lookup_elem(&blocked_ips_v6, &key);
    if (info) {
        __sync_fetch_and_add(&info->hit_count, 1);
        return 1;
    }
    return 0;
}

// ============================================================================
// 辅助函数：TCP 解析
// ============================================================================

/**
 * 检查是否是 TCP SYN 包（不带 ACK）
 * 
 * SYN 包标志位：
 *  - SYN = 1：初始化连接
 *  - ACK = 0：不是对现有连接的确认
 * 
 * 这个函数用于检测新连接请求，通常用于 SYN Flood 检测
 * 
 * @param iph IP 头指针
 * @param data_end 数据包结束位置
 * @return 1 = 是 SYN 包，0 = 不是
 */
static __always_inline int is_tcp_syn(struct iphdr *iph, void *data_end) {
    // 检查协议是否为 TCP
    if (iph->protocol != IPPROTO_TCP)
        return 0;
    
    // 计算 IP 头长度
    // ihl = IP Header Length，单位是 32 位字，所以要乘以 4 得到字节数
    __u32 ip_hdr_len = iph->ihl * 4;
    
    // TCP 头位于 IP 头之后
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    
    // 边界检查：确保 TCP 头完全在数据包内
    if ((void *)(tcph + 1) > data_end)
        return 0;
    
    // 检查 SYN=1 且 ACK=0（新连接请求）
    return tcph->syn && !tcph->ack;
}

/**
 * 检查 IPv6 是否是 TCP SYN 包
 * 
 * IPv6 中 TCP 头直接跟在 IPv6 头之后（假设没有扩展头）
 * 
 * @param ip6h IPv6 头指针
 * @param data_end 数据包结束位置
 * @return 1 = 是 SYN 包，0 = 不是
 */
static __always_inline int is_tcp_syn_v6(struct ipv6hdr *ip6h, void *data_end) {
    // 检查 next header 是否为 TCP
    // 注意：实际应用中可能需要处理扩展头，这里简化假设没有扩展头
    if (ip6h->nexthdr != IPPROTO_TCP)
        return 0;
    
    // TCP 头位于 IPv6 头之后
    struct tcphdr *tcph = (void *)(ip6h + 1);
    
    // 边界检查
    if ((void *)(tcph + 1) > data_end)
        return 0;
    
    return tcph->syn && !tcph->ack;
}

// ============================================================================
// 辅助函数：安全获取 IPv6 源地址
// ============================================================================

/**
 * 安全复制 IPv6 源地址到缓冲区（避免对齐问题）
 * 
 * 直接访问 IPv6 地址可能导致对齐问题，使用 memcpy 是推荐的做法
 * 
 * @param ip6h IPv6 头指针
 * @param dst 目标缓冲区（16 字节）
 */
static __always_inline void get_ipv6_saddr(struct ipv6hdr *ip6h, __u8 dst[16]) {
    __builtin_memcpy(dst, &ip6h->saddr, 16);
}

// ============================================================================
// XDP 主程序
// ============================================================================

/**
 * XDP 防火墙程序主入口
 * 
 * 处理流程：
 * 1. 解析以太网头，判断协议类型
 * 2. 根据协议类型（IPv4/IPv6）分别处理
 * 3. 对每个数据包进行白名单检查和黑名单检查
 * 4. 返回 XDP_DROP（丢弃）或 XDP_PASS（放行）
 * 
 * 性能：
 * - 每个 CPU 核可处理数百万包/秒
 * - 内核态处理，零用户态上下文切换开销
 * - 支持单 IPv4/IPv6 和 CIDR 前缀匹配
 */
SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // 统计总包数（用于 PPS 计算）
    update_stats(STATS_TOTAL);
    
    // ===== 第一步：解析以太网头 =====
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        // 包太短，无法访问以太网头，直接放行
        return XDP_PASS;
    }
    
    // 从以太网头中获取协议类型
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    
    // ===== 第二步：根据协议类型分别处理 =====
    
    if (eth_proto == ETH_P_IP) {
        // ===== IPv4 处理路径 =====
        
        // 解析 IP 头
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            // IP 头不完整
            return XDP_PASS;
        }
        
        // 检查 IP 头长度合法性
        __u32 ip_hdr_len = iph->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr)) {
            // IP 头长度不合法
            return XDP_PASS;
        }
        if ((void *)iph + ip_hdr_len > data_end) {
            // IP 头超出数据包范围
            return XDP_PASS;
        }
        
        // 获取源 IP 地址（网络字节序）
        __u32 src_ip = iph->saddr;
        
        // 检测是否是 TCP SYN
        int is_syn = is_tcp_syn(iph, data_end);
        
        // 统计 TCP SYN 包（用于检测 SYN Flood）
        if (is_syn) {
            update_stats(STATS_TCP_SYN);
        }
        
        // 更新 per-IP 统计（用于单IP PPS检测）
        update_per_ip_stats_v4(src_ip, is_syn);
        
        // ===== 白名单检查（优先级最高）=====
        
        // 1. 内置白名单检查（硬编码，最快，无 map 查询开销）
        // 包括：127.x.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x 等
        if (is_builtin_whitelist_v4(src_ip)) {
            update_stats(STATS_WHITELISTED);
            update_stats(STATS_PASSED);
            return XDP_PASS;
        }
        
        // 2. 动态白名单检查（LPM Trie，支持 CIDR）
        if (check_dynamic_whitelist_v4(src_ip)) {
            update_stats(STATS_WHITELISTED);
            update_stats(STATS_PASSED);
            return XDP_PASS;
        }
        
        // ===== 黑名单检查 =====
        if (check_ipv4_blocked(src_ip)) {
            update_stats(STATS_DROPPED);
            return XDP_DROP;
        }
        
    } else if (eth_proto == ETH_P_IPV6) {
        // ===== IPv6 处理路径 =====
        
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) {
            // IPv6 头不完整
            return XDP_PASS;
        }
        
        // 安全复制 IPv6 源地址（避免对齐问题）
        __u8 src_addr[16];
        get_ipv6_saddr(ip6h, src_addr);
        
        // 检测是否是 TCP SYN
        int is_syn_v6 = is_tcp_syn_v6(ip6h, data_end);
        
        // 统计 TCP SYN 包
        if (is_syn_v6) {
            update_stats(STATS_TCP_SYN);
        }
        
        // 更新 per-IP 统计
        update_per_ip_stats_v6(src_addr, is_syn_v6);
        
        // ===== 白名单检查 =====
        
        // 1. 内置白名单（::1, fe80::, ff00::, 等）
        if (is_builtin_whitelist_v6(src_addr)) {
            update_stats(STATS_WHITELISTED);
            update_stats(STATS_PASSED);
            return XDP_PASS;
        }
        
        // 2. 动态白名单（LPM Trie）
        if (check_dynamic_whitelist_v6(src_addr)) {
            update_stats(STATS_WHITELISTED);
            update_stats(STATS_PASSED);
            return XDP_PASS;
        }
        
        // ===== 黑名单检查 =====
        if (check_ipv6_blocked(src_addr)) {
            update_stats(STATS_DROPPED);
            return XDP_DROP;
        }
    }
    
    // 未被拦截，放行
    update_stats(STATS_PASSED);
    return XDP_PASS;
}

// ============================================================================
// 可选程序：仅拦截 TCP SYN（新连接），允许已建立的连接
// ============================================================================

/**
 * 替代程序：TCP SYN 只白名单模式
 * 
 * 相比主程序：
 * - 只拦截 TCP SYN 包（新连接请求）
 * - 允许已建立连接的数据包通过
 * - 适用于 SYN Flood 防护而不影响既有连接
 */
SEC("xdp")
int xdp_firewall_tcp_only(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // 统计总包数
    update_stats(STATS_TOTAL);
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    
    // 只处理 TCP 协议
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    __u32 ip_hdr_len = iph->ihl * 4;
    if ((void *)iph + ip_hdr_len > data_end)
        return XDP_PASS;
    
    // 解析 TCP 头
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;
    
    // 统计所有 TCP SYN
    if (tcph->syn && !tcph->ack) {
        update_stats(STATS_TCP_SYN);
    }
    
    // 只拦截 SYN 包（新连接请求）
    // ACK 位被设置或 SYN 未被设置表示这是已建立连接的数据包
    if (!tcph->syn || tcph->ack)
        return XDP_PASS;
    
    // 获取源 IP
    __u32 src_ip = iph->saddr;
    
    // 白名单检查
    if (is_builtin_whitelist_v4(src_ip)) {
        update_stats(STATS_WHITELISTED);
        update_stats(STATS_PASSED);
        return XDP_PASS;
    }
    
    if (check_dynamic_whitelist_v4(src_ip)) {
        update_stats(STATS_WHITELISTED);
        update_stats(STATS_PASSED);
        return XDP_PASS;
    }
    
    // 黑名单检查
    if (check_ipv4_blocked(src_ip)) {
        update_stats(STATS_DROPPED);
        return XDP_DROP;
    }
    
    update_stats(STATS_PASSED);
    return XDP_PASS;
}

// 许可证（必须是 GPL 才能使用部分 BPF 辅助函数）
char LICENSE[] SEC("license") = "GPL";