// Compile-time ABI guard for the frozen XDP userspace header.
#include "xdp_firewall.h"

#include <stddef.h>

_Static_assert(sizeof(struct xdp_fw_opts) == 40, "xdp_fw_opts size changed");
_Static_assert(offsetof(struct xdp_fw_opts, verbose) == 32,
               "xdp_fw_opts.verbose offset changed");
_Static_assert(offsetof(struct xdp_fw_opts, force_generic_mode) == 36,
               "xdp_fw_opts.force_generic_mode offset changed");
_Static_assert(sizeof(struct xdp_fw_ban_info) == 16, "xdp_fw_ban_info size changed");
_Static_assert(sizeof(struct xdp_fw_stats) == 56, "xdp_fw_stats size changed");
_Static_assert(sizeof(struct xdp_fw_pps_stats) == 48, "xdp_fw_pps_stats size changed");
_Static_assert(sizeof(struct xdp_fw_per_ip_stats) == 16,
               "xdp_fw_per_ip_stats size changed");
_Static_assert(sizeof(struct xdp_fw_ip_stats_entry) == 24,
               "xdp_fw_ip_stats_entry size changed");
_Static_assert(sizeof(struct xdp_fw_ip6_stats_entry) == 32,
               "xdp_fw_ip6_stats_entry size changed");
