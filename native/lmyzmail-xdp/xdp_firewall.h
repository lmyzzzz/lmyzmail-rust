// SPDX-License-Identifier: Apache-2.0
// XDP Firewall 用户态 API 头文件（增强版）
// 
// 此头文件定义了 XDP 防火墙的所有公共接口
// 供 Java FFM 或其他用户态程序调用
// 
// v1.1 修复：
//  - 结构体对齐和字段顺序修正
//  - xdp_fw_opts 字段顺序修正（verbose 在 force_generic_mode 之前）
//  - xdp_fw_stats 添加了缺失的字段
//  - 添加 per-IP 统计 API

#ifndef XDP_FIREWALL_H
#define XDP_FIREWALL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 版本信息
// ============================================================================

#define XDP_FW_VERSION_MAJOR    1
#define XDP_FW_VERSION_MINOR    1
#define XDP_FW_VERSION_PATCH    0

// ============================================================================
// 错误码定义
// ============================================================================

// 成功
#define XDP_FW_OK           0       // 成功

// 权限错误
#define XDP_FW_ERR_PERM     -1      // 权限不足（需要 root 或 CAP_BPF+CAP_NET_ADMIN）

// 设备错误
#define XDP_FW_ERR_NODEV    -2      // 网卡不存在或无法访问

// 程序加载错误
#define XDP_FW_ERR_LOAD     -3      // 加载 BPF 程序失败（可能是 BPF 格式错误或不兼容）

// 程序附加错误
#define XDP_FW_ERR_ATTACH   -4      // 附加 XDP 程序到网卡失败（可能是驱动不支持）

// Map 操作错误
#define XDP_FW_ERR_MAP      -5      // BPF Map 操作失败（通常表示 map 已满或其他操作问题）

// 初始化状态错误
#define XDP_FW_ERR_INIT     -6      // 防火墙未初始化或初始化失败

// 重复初始化错误
#define XDP_FW_ERR_ALREADY  -7      // 防火墙已初始化，不允许重复初始化

// 内存错误
#define XDP_FW_ERR_NOMEM    -8      // 内存不足（通常表示 eBPF map 已满）

// 条目不存在错误
#define XDP_FW_ERR_NOENT    -9      // 请求的条目不存在（例如尝试解封未被封禁的 IP）

// ============================================================================
// 封禁原因代码
// ============================================================================

// 手动封禁
#define BAN_REASON_MANUAL       0   // 管理员手动封禁

// 速率限制
#define BAN_REASON_RATE_LIMIT   1   // 因超过速率限制而封禁

// SYN Flood 攻击
#define BAN_REASON_SYN_FLOOD    2   // 检测到 SYN Flood 攻击

// 外部黑名单
#define BAN_REASON_BLACKLIST    3   // 来自外部黑名单（如 Spamhaus）

// 机器人/爬虫
#define BAN_REASON_BOT          4   // 检测到机器人或爬虫行为

// 垃圾邮件
#define BAN_REASON_SPAM         5   // 来自已知垃圾邮件源

// 端口扫描
#define BAN_REASON_SCAN         6   // 检测到端口扫描行为

// 其他原因
#define BAN_REASON_OTHER        99  // 其他原因

// ============================================================================
// 数据结构
// ============================================================================

/**
 * 初始化选项结构体
 * 
 * v1.1 修复：字段顺序已纠正
 * 对应顺序：ifname, bpf_obj_path, prog_name, pin_base_path, verbose, force_generic_mode
 */
struct xdp_fw_opts {
    const char *ifname;         // 网卡名称，必填（例如 "eth0", "en0"）
    const char *bpf_obj_path;   // BPF 对象文件路径，必填（例如 "/path/to/xdp_firewall.bpf.o"）
    const char *prog_name;      // BPF 程序名称，可选，默认 "xdp_firewall_prog"
    const char *pin_base_path;  // Map pin 路径，可选，默认 "/sys/fs/bpf/lmyzmail"
    int verbose;                // 详细日志模式（1 = 启用，0 = 禁用）
    int force_generic_mode;     // 强制使用 generic/SKB 模式（1 = 是，0 = 否）
};

/**
 * 单个 IP 的封禁信息
 */
struct xdp_fw_ban_info {
    uint64_t timestamp;         // 封禁时间戳（纳秒）
    uint32_t reason;            // 封禁原因代码（BAN_REASON_* 常量）
    uint32_t hit_count;         // 该 IP 触发规则的次数
};

/**
 * 统计信息结构体
 * 
 * v1.1 修复：添加了缺失的字段
 * - packets_total：总的数据包数（用于计算总 PPS）
 * - packets_syn：TCP SYN 包数（用于计算 SYN PPS 和检测 SYN Flood）
 * - packets_whitelisted：白名单放行的包数
 * - whitelist_count：IPv4 白名单条目数
 * - whitelist_v6_count：IPv6 白名单条目数
 */
struct xdp_fw_stats {
    uint64_t packets_passed;    // 放行的包数（通过了所有检查的包）
    uint64_t packets_dropped;   // 丢弃的包数（被黑名单拦截的包）
    uint64_t packets_total;     // 总包数（用于计算 PPS）(新增 v1.1)
    uint64_t packets_syn;       // TCP SYN 包数（用于检测 SYN Flood）(新增 v1.1)
    uint64_t packets_whitelisted; // 白名单放行的包数 (新增 v1.1)
    uint32_t banned_ips_count;  // 当前封禁的 IPv4 地址数量
    uint32_t banned_ips_v6_count; // 当前封禁的 IPv6 地址数量
    uint32_t whitelist_count;   // IPv4 白名单条目数 (新增 v1.1)
    uint32_t whitelist_v6_count; // IPv6 白名单条目数 (新增 v1.1)
};

/**
 * PPS 统计信息
 * 用于检测 DDoS 和 SYN Flood 攻击
 */
struct xdp_fw_pps_stats {
    uint64_t pps;               // 总 PPS（每秒包数）
    uint64_t syn_pps;           // SYN PPS（每秒 SYN 包数）
    uint64_t dropped_pps;       // 丢弃 PPS（每秒丢弃包数）
    uint64_t passed_pps;        // 放行 PPS（每秒放行包数）
    uint64_t timestamp_ns;      // 统计时间戳（纳秒，相对于 CLOCK_MONOTONIC）
    uint64_t interval_ns;       // 统计间隔（纳秒）
};

/**
 * Per-IP 统计信息
 * 用于单IP PPS检测
 */
struct xdp_fw_per_ip_stats {
    uint64_t packets;       // 总包数
    uint64_t syn_packets;   // SYN包数
};

/**
 * IPv4 统计条目（用于批量获取）
 */
struct xdp_fw_ip_stats_entry {
    uint32_t ip;                        // IPv4地址（主机字节序）
    struct xdp_fw_per_ip_stats stats;   // 统计数据
};

/**
 * IPv6 统计条目
 */
struct xdp_fw_ip6_stats_entry {
    uint8_t ip[16];                     // IPv6地址
    struct xdp_fw_per_ip_stats stats;   // 统计数据
};

// ============================================================================
// 初始化与关闭
// ============================================================================

/**
 * 初始化 XDP 防火墙
 * 
 * 此函数会：
 * 1. 检查权限和系统环境
 * 2. 加载 BPF 程序到内核
 * 3. 将 XDP 程序附加到网卡
 * 4. 初始化统计计数器
 * 
 * 调用成功后，防火墙开始工作
 * 
 * @param opts 初始化选项结构体指针
 * @return XDP_FW_OK 表示成功，其他为错误码
 * 
 * 示例：
 *   struct xdp_fw_opts opts = {
 *       .ifname = "eth0",
 *       .bpf_obj_path = "/path/to/xdp_firewall.bpf.o",
 *       .verbose = 1
 *   };
 *   int result = xdp_fw_init(&opts);
 */
int xdp_fw_init(const struct xdp_fw_opts *opts);

/**
 * 关闭 XDP 防火墙（保留 pinned maps）
 * 
 * 此函数会：
 * 1. 从网卡上分离 XDP 程序
 * 2. 关闭 BPF 对象
 * 3. 保留 pinned maps 中的数据（用于重新连接）
 * 
 * 调用此函数后，防火墙停止工作但数据被保留
 */
void xdp_fw_close(void);

/**
 * 销毁 XDP 防火墙（删除所有资源）
 * 
 * 此函数会：
 * 1. 从网卡上分离 XDP 程序
 * 2. 关闭 BPF 对象
 * 3. 删除所有 pinned maps 中的数据
 * 
 * 调用此函数后，所有防火墙数据都被删除
 */
void xdp_fw_destroy(void);

/**
 * 检查是否已初始化
 * 
 * @return 1 表示已初始化，0 表示未初始化
 */
int xdp_fw_is_initialized(void);

// ============================================================================
// 黑名单操作 - IPv4
// ============================================================================

/**
 * 封禁单个 IPv4 地址
 * 
 * @param ip IPv4 地址（主机字节序，如 0xC0A80101 表示 192.168.1.1）
 * @param reason 封禁原因代码（BAN_REASON_* 常量之一）
 * @return XDP_FW_OK 成功，其他为错误码
 */
int xdp_fw_ban_ip(uint32_t ip, uint32_t reason);

/**
 * 解封单个 IPv4 地址
 * 
 * @param ip IPv4 地址（主机字节序）
 * @return XDP_FW_OK 成功，XDP_FW_ERR_NOENT 表示该 IP 未被封禁
 */
int xdp_fw_unban_ip(uint32_t ip);

/**
 * 批量封禁 IPv4 地址
 * 
 * @param ips IP 地址数组（主机字节序）
 * @param count 数组中的元素个数
 * @param reason 封禁原因代码
 * @return 成功封禁的数量（0 到 count 之间）
 */
int xdp_fw_ban_ips_batch(const uint32_t *ips, int count, uint32_t reason);

/**
 * 批量解封 IPv4 地址
 * 
 * @param ips IP 地址数组（主机字节序）
 * @param count 数组中的元素个数
 * @return 成功解封的数量
 */
int xdp_fw_unban_ips_batch(const uint32_t *ips, int count);

/**
 * 检查 IPv4 是否被封禁
 * 
 * @param ip IPv4 地址（主机字节序）
 * @param info_out 输出参数，用于接收封禁信息（可为 NULL）
 * @return 1 = 已封禁，0 = 未封禁，<0 = 错误
 */
int xdp_fw_is_banned(uint32_t ip, struct xdp_fw_ban_info *info_out);

/**
 * 获取所有被封禁的 IPv4 地址
 * 
 * @param out_ips 输出数组，用于存储 IP 地址（主机字节序）
 * @param max_count 输出数组的最大容量
 * @return 实际返回的 IP 数量（0 到 max_count 之间），<0 = 错误
 */
int xdp_fw_get_banned_ips(uint32_t *out_ips, int max_count);

/**
 * 获取当前封禁 IPv4 数量
 * 
 * @return 被封禁的 IPv4 地址总数
 */
int xdp_fw_get_banned_count(void);

/**
 * 清空所有 IPv4 封禁记录
 * 
 * @return 被清除的 IPv4 地址数量
 */
int xdp_fw_clear_all(void);

// ============================================================================
// 黑名单操作 - IPv6
// ============================================================================

/**
 * 封禁 IPv6 地址
 * 
 * @param ipv6_bytes 16 字节的 IPv6 地址（网络字节序）
 * @param reason 封禁原因代码
 * @return XDP_FW_OK 成功
 */
int xdp_fw_ban_ipv6(const uint8_t ipv6_bytes[16], uint32_t reason);

/**
 * 解封 IPv6 地址
 * 
 * @param ipv6_bytes 16 字节的 IPv6 地址（网络字节序）
 * @return XDP_FW_OK 成功
 */
int xdp_fw_unban_ipv6(const uint8_t ipv6_bytes[16]);

/**
 * 检查 IPv6 是否被封禁
 * 
 * @param ipv6_bytes 16 字节的 IPv6 地址（网络字节序）
 * @param info_out 输出参数，用于接收封禁信息（可为 NULL）
 * @return 1 = 已封禁，0 = 未封禁，<0 = 错误
 */
int xdp_fw_is_banned_ipv6(const uint8_t ipv6_bytes[16], struct xdp_fw_ban_info *info_out);

/**
 * 获取所有被封禁的 IPv6 地址
 * 
 * @param out_ipv6s 输出数组，每个元素是 16 字节的 IPv6 地址
 * @param max_count 最大数量
 * @return 实际返回的 IPv6 数量
 */
int xdp_fw_get_banned_ipv6(uint8_t (*out_ipv6s)[16], int max_count);

/**
 * 获取当前封禁 IPv6 数量
 * 
 * @return 被封禁的 IPv6 地址总数
 */
int xdp_fw_get_banned_count_v6(void);

/**
 * 清空所有 IPv6 封禁记录
 * 
 * @return 被清除的 IPv6 地址数量
 */
int xdp_fw_clear_all_v6(void);

// ============================================================================
// 白名单操作 - IPv4
// ============================================================================

/**
 * 添加 IPv4 地址到内核白名单（支持 CIDR）
 * 
 * @param ip IPv4 地址（主机字节序）
 * @param prefixlen 前缀长度（1-32），32 表示单个 IP，24 表示 /24 网段
 * @return XDP_FW_OK 成功
 * 
 * 示例：
 *   xdp_fw_whitelist_add(0xC0A80000, 16)  // 添加 192.168.0.0/16
 *   xdp_fw_whitelist_add(0x08080808, 32)  // 添加单个 IP 8.8.8.8
 */
int xdp_fw_whitelist_add(uint32_t ip, uint32_t prefixlen);

/**
 * 从白名单移除 IPv4 地址
 * 
 * @param ip IPv4 地址（主机字节序）
 * @param prefixlen 前缀长度（必须与添加时相同）
 * @return XDP_FW_OK 成功
 */
int xdp_fw_whitelist_remove(uint32_t ip, uint32_t prefixlen);

/**
 * 检查 IPv4 地址是否在白名单中
 * 
 * @param ip IPv4 地址（主机字节序）
 * @return 1 = 在白名单中，0 = 不在，<0 = 错误
 */
int xdp_fw_whitelist_check(uint32_t ip);

/**
 * 获取 IPv4 白名单条目数量
 * 
 * @return 白名单中的 IPv4 条目数
 */
int xdp_fw_whitelist_count(void);

/**
 * 清空所有 IPv4 动态白名单条目
 * 
 * @return 清除的条目数
 */
int xdp_fw_whitelist_clear(void);

// ============================================================================
// 白名单操作 - IPv6
// ============================================================================

/**
 * 添加 IPv6 地址到白名单（支持 CIDR）
 * 
 * @param ipv6_bytes 16 字节的 IPv6 地址（网络字节序）
 * @param prefixlen 前缀长度（1-128）
 * @return XDP_FW_OK 成功
 */
int xdp_fw_whitelist_add_v6(const uint8_t ipv6_bytes[16], uint32_t prefixlen);

/**
 * 从白名单移除 IPv6 地址
 * 
 * @param ipv6_bytes 16 字节的 IPv6 地址（网络字节序）
 * @param prefixlen 前缀长度（必须与添加时相同）
 * @return XDP_FW_OK 成功
 */
int xdp_fw_whitelist_remove_v6(const uint8_t ipv6_bytes[16], uint32_t prefixlen);

/**
 * 检查 IPv6 是否在白名单中
 * 
 * @param ipv6_bytes 16 字节的 IPv6 地址（网络字节序）
 * @return 1 = 在白名单中，0 = 不在，<0 = 错误
 */
int xdp_fw_whitelist_check_v6(const uint8_t ipv6_bytes[16]);

/**
 * 获取 IPv6 白名单条目数量
 * 
 * @return 白名单中的 IPv6 条目数
 */
int xdp_fw_whitelist_count_v6(void);

/**
 * 清空所有 IPv6 动态白名单条目
 * 
 * @return 清除的条目数
 */
int xdp_fw_whitelist_clear_v6(void);

// ============================================================================
// 统计与监控
// ============================================================================

/**
 * 获取统计信息
 * 
 * @param stats_out 输出参数，用于接收统计数据
 * @return XDP_FW_OK 成功
 */
int xdp_fw_get_stats(struct xdp_fw_stats *stats_out);

/**
 * 重置统计计数器
 * 
 * @return XDP_FW_OK 成功
 */
int xdp_fw_reset_stats(void);

/**
 * 获取 PPS 统计数据
 * 
 * 此函数会计算自上次调用以来的 PPS 数据
 * 首次调用返回全 0，后续调用返回实际 PPS 值
 * 
 * @param stats_out 输出参数，用于接收 PPS 统计
 * @return XDP_FW_OK 成功
 */
int xdp_fw_get_pps(struct xdp_fw_pps_stats *stats_out);

/**
 * 重置 PPS 统计基准
 * 
 * 在重置统计计数器后应调用此函数，
 * 以建立新的 PPS 计算基线
 */
void xdp_fw_reset_pps_baseline(void);

// ============================================================================
// Per-IP 统计 API（用于单IP PPS检测）
// ============================================================================

/**
 * 获取所有IPv4的per-IP统计
 * 
 * @param entries_out 输出数组
 * @param max_count 最大条目数
 * @return 实际返回的条目数，<0表示错误
 */
int xdp_fw_get_all_ip_stats_v4(struct xdp_fw_ip_stats_entry *entries_out, int max_count);

/**
 * 获取所有IPv6的per-IP统计
 * 
 * @param entries_out 输出数组
 * @param max_count 最大条目数
 * @return 实际返回的条目数，<0表示错误
 */
int xdp_fw_get_all_ip_stats_v6(struct xdp_fw_ip6_stats_entry *entries_out, int max_count);

/**
 * 清除所有per-IP统计
 * 
 * @return 清除的条目数
 */
int xdp_fw_clear_per_ip_stats(void);

/**
 * 获取per-IP统计map中的条目数
 * 
 * @return IPv4条目数 + IPv6条目数
 */
int xdp_fw_get_per_ip_stats_count(void);

// ============================================================================
// 工具函数
// ============================================================================

/**
 * 检查权限
 * 
 * 检查当前进程是否具有运行 XDP 防火墙所需的权限
 * 需要以下条件之一：
 * - 以 root 身份运行
 * - 具有 CAP_BPF + CAP_NET_ADMIN 能力
 * 
 * @return 1 = 有权限，0 = 无权限
 */
int xdp_fw_check_permissions(void);

/**
 * 获取最后一次错误信息
 * 
 * @return 错误信息字符串指针（内部缓冲区，不应自行释放）
 */
const char* xdp_fw_get_last_error(void);

/**
 * 将错误码转换为可读文本
 * 
 * @param err 错误码
 * @return 错误描述字符串
 */
const char* xdp_fw_strerror(int err);

/**
 * 获取版本字符串
 * 
 * @return 版本字符串（例如 "1.1.0"）
 */
const char* xdp_fw_version(void);

/**
 * IPv4 字符串转整数（主机字节序）
 * 
 * @param ip_str IP 字符串，如 "192.168.1.1"
 * @param ip_out 输出参数，用于存储转换后的整数
 * @return 0 = 成功，-1 = 失败
 */
int xdp_fw_ip_from_string(const char *ip_str, uint32_t *ip_out);

/**
 * IPv4 整数转字符串
 * 
 * @param ip 主机字节序 IP
 * @param buf 输出缓冲区（至少 16 字节）
 * @param buf_len 缓冲区长度
 * @return buf 指针
 */
char* xdp_fw_ip_to_string(uint32_t ip, char *buf, int buf_len);

#ifdef __cplusplus
}
#endif

#endif // XDP_FIREWALL_H