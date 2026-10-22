#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run this launcher as root so it can create benchmark isolation" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository=$(cd -- "${script_dir}/../.." && pwd -P)
launcher=${script_dir}/$(basename -- "${BASH_SOURCE[0]}")
runner="${script_dir}/smtp-endpoint-throughput-v1.py"
venv_python="${repository}/blackbox/.venv/bin/python"
proxy_binary="${repository}/target/x86_64-unknown-linux-gnu/release/lmyzmail-benchmark-proxy"

cgroup_root=${LMYZMAIL_BENCHMARK_CGROUP_ROOT:-/sys/fs/cgroup}
proc_root=${LMYZMAIL_BENCHMARK_PROC_ROOT:-/proc}
state_root=${LMYZMAIL_BENCHMARK_STATE_ROOT:-/var/lib/lmyzmail-benchmark}
runtime_root=${LMYZMAIL_BENCHMARK_RUNTIME_ROOT:-/run/lmyzmail-benchmark-root}
attestation_root=${LMYZMAIL_BENCHMARK_ATTESTATION_ROOT:-/run/lmyzmail-benchmark-attestations}
proxy_attestation_root=${LMYZMAIL_BENCHMARK_PROXY_ATTESTATION_ROOT:-${state_root}/proxy-attestations}
journal_root=${state_root}/journal
image_root=${state_root}/images
artifact_root=${state_root}/artifacts
mounts_root=${runtime_root}/mounts
persistent_group=${cgroup_root}/lmyzmail-benchmark-root
housekeeping_group=${cgroup_root}/lmyzmail-benchmark-housekeeping
benchmark_lock=${runtime_root}/smtp-endpoint-throughput.lock

benchmark_user=${LMYZMAIL_BENCHMARK_USER:-$(stat -c '%U' -- "${repository}")}
benchmark_cpu=${LMYZMAIL_BENCHMARK_CPU:-23}
io_bytes_per_second=${LMYZMAIL_BENCHMARK_IO_BPS:-500000000}
max_pids=${LMYZMAIL_BENCHMARK_MAX_PIDS:-8192}
memory_high_bytes=${LMYZMAIL_BENCHMARK_MEMORY_HIGH_BYTES:-7516192768}
max_memory_bytes=${LMYZMAIL_BENCHMARK_MAX_MEMORY_BYTES:-8589934592}
nofile_limit=${LMYZMAIL_BENCHMARK_NOFILE_LIMIT:-8192}
host_reserve_bytes=${LMYZMAIL_BENCHMARK_HOST_RESERVE_BYTES:-10737418240}
housekeeping_cpu_limit=8
runner_gate_timeout_seconds=5

for command in dd fallocate findmnt flock install losetup mkfifo mkfs.ext4 mount mv \
    prlimit realpath setpriv sha256sum stat taskset umount unshare; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "required benchmark command is unavailable: ${command}" >&2
        exit 2
    fi
done
if [[ ! -f ${runner} ]]; then
    echo "benchmark runner is missing: ${runner}" >&2
    exit 2
fi
if [[ ! -x ${venv_python} ]]; then
    echo "black-box Python runtime is missing: ${venv_python}" >&2
    exit 2
fi
if ! id -- "${benchmark_user}" >/dev/null 2>&1; then
    echo "benchmark workspace must be owned by a non-root user" >&2
    exit 2
fi

benchmark_uid=$(id -u -- "${benchmark_user}")
benchmark_gid=$(id -g -- "${benchmark_user}")
benchmark_passwd=$(getent passwd "${benchmark_uid}")
if [[ -z ${benchmark_passwd} ]]; then
    echo "benchmark UID ${benchmark_uid} has no passwd entry" >&2
    exit 2
fi
IFS=: read -r benchmark_login _ passwd_uid passwd_gid _ benchmark_home benchmark_shell \
    <<<"${benchmark_passwd}"
if [[ ${passwd_uid} != "${benchmark_uid}" || ${passwd_gid} != "${benchmark_gid}" ]]; then
    echo "benchmark passwd entry does not match its numeric UID/GID" >&2
    exit 2
fi
benchmark_shell=${benchmark_shell:-/bin/sh}
if [[ ${benchmark_uid} -eq 0 ]]; then
    echo "benchmark user must have a nonzero numeric UID" >&2
    exit 2
fi
if [[ ! ${benchmark_cpu} =~ ^[0-9]+$ ]]; then
    echo "LMYZMAIL_BENCHMARK_CPU must be one logical CPU number" >&2
    exit 2
fi
if [[ ! ${io_bytes_per_second} =~ ^[1-9][0-9]*$ ]]; then
    echo "LMYZMAIL_BENCHMARK_IO_BPS must be a positive integer" >&2
    exit 2
fi
if [[ ! ${max_pids} =~ ^[1-9][0-9]*$ ]]; then
    echo "LMYZMAIL_BENCHMARK_MAX_PIDS must be a positive integer" >&2
    exit 2
fi
if [[ ! ${max_memory_bytes} =~ ^[1-9][0-9]*$ ]]; then
    echo "LMYZMAIL_BENCHMARK_MAX_MEMORY_BYTES must be a positive integer" >&2
    exit 2
fi
if [[ ! ${memory_high_bytes} =~ ^[1-9][0-9]*$ \
    || ${memory_high_bytes} -ge ${max_memory_bytes} ]]; then
    echo "LMYZMAIL_BENCHMARK_MEMORY_HIGH_BYTES must be positive and below memory.max" >&2
    exit 2
fi
if [[ ! ${nofile_limit} =~ ^[1-9][0-9]*$ ]]; then
    echo "LMYZMAIL_BENCHMARK_NOFILE_LIMIT must be a positive integer" >&2
    exit 2
fi
if [[ ! ${host_reserve_bytes} =~ ^[1-9][0-9]*$ ]]; then
    echo "LMYZMAIL_BENCHMARK_HOST_RESERVE_BYTES must be a positive integer" >&2
    exit 2
fi
if [[ ! ${housekeeping_cpu_limit} =~ ^[1-9][0-9]*$ ]]; then
    echo "housekeeping CPU limit must be a positive integer" >&2
    exit 2
fi

derive_housekeeping_cpus() {
    "${venv_python}" - "$1" "$2" "$3" <<'PY'
import sys

selected = int(sys.argv[2])
limit = int(sys.argv[3])
if limit <= 0:
    raise SystemExit("housekeeping CPU limit must be positive")
cpus = set()
for part in sys.argv[1].split(","):
    bounds = part.split("-", 1)
    start = int(bounds[0])
    stop = int(bounds[-1])
    if stop < start:
        raise SystemExit("invalid root cpuset")
    cpus.update(range(start, stop + 1))
if selected not in cpus:
    raise SystemExit("benchmark CPU is outside the root cpuset")
cpus.remove(selected)
ordered = sorted(cpus)[:limit]
if not ordered:
    raise SystemExit("benchmark requires at least one housekeeping CPU")
ranges = []
start = previous = ordered[0]
for cpu in ordered[1:]:
    if cpu == previous + 1:
        previous = cpu
        continue
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    start = previous = cpu
ranges.append(str(start) if start == previous else f"{start}-{previous}")
print(",".join(ranges))
PY
}

root_cpus=$(<"${cgroup_root}/cpuset.cpus.effective")
root_mems=$(<"${cgroup_root}/cpuset.mems.effective")
if [[ -z ${root_cpus} || -z ${root_mems} ]]; then
    echo "could not resolve cgroup cpuset topology" >&2
    exit 2
fi
if ! taskset --cpu-list "${benchmark_cpu}" true >/dev/null 2>&1; then
    echo "CPU ${benchmark_cpu} is outside cpuset.cpus.effective=${root_cpus}" >&2
    exit 2
fi
housekeeping_cpus=$(derive_housekeeping_cpus \
    "${root_cpus}" "${benchmark_cpu}" "${housekeeping_cpu_limit}")
if ! taskset --cpu-list "${housekeeping_cpus}" true >/dev/null 2>&1; then
    echo "could not construct housekeeping cpuset excluding CPU ${benchmark_cpu}" >&2
    exit 2
fi
for controller in cpuset cpu io memory pids; do
    if ! grep -qw -- "${controller}" "${cgroup_root}/cgroup.controllers"; then
        echo "required cgroup v2 controller is unavailable: ${controller}" >&2
        exit 2
    fi
done

install -d -m 0700 -o root -g root \
    "${state_root}" "${journal_root}" "${image_root}" "${artifact_root}"
install -d -m 0755 -o root -g root "${runtime_root}" "${attestation_root}"
install -d -m 0711 -o root -g root "${mounts_root}"
install -d -m 0700 -o root -g root "${proxy_attestation_root}"

exec {benchmark_lock_fd}>"${benchmark_lock}"
if ! flock -n "${benchmark_lock_fd}"; then
    echo "another lmyzmail SMTP endpoint benchmark is already running" >&2
    exit 2
fi

benchmark_group=
harness_group=
workload_group=
services_group=
migration_socket=
runner_gate=
run_id=
intent_path=
done_path=
runner_success_path=
partial_output_publish_path=
partial_checkpoint_publish_path=
image_path=
output_artifact=
checkpoint_artifact=
quota_mount=
loop_device=
loop_device_id=
backing_device_id=
runner_pid=
runner_start_time=
runner_registered=0
runner_finished=0
runner_reaped=0
watchdog_pid=
watchdog_control_fd=
watchdog_status_fd=
watchdog_started=0
watchdog_failed=0
cleanup_finalized=0
cleanup_lazy_used=0
final_output=
provisional_output=
provisional_checkpoint=
final_checkpoint=
formal_run=1
java_small_baseline_run=0
profiler_run=0
rust_filesystem_fsync=not-applicable
image_bytes=0
disk_budget_gib=20
external_attestation_path=
external_attestation_sha256=
runner_output_fd=
runner_checkpoint_fd=

fsync_file_and_parent() {
    local path=$1
    "${venv_python}" - "${path}" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
with path.open("rb") as stream:
    os.fsync(stream.fileno())
descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

fsync_directory() {
    local path=$1
    "${venv_python}" - "${path}" <<'PY'
import os
import pathlib
import sys

descriptor = os.open(pathlib.Path(sys.argv[1]), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

write_journal_once() {
    local path=$1 payload=$2 temporary directory metadata
    temporary=${path}.tmp.$$
    directory=$(dirname -- "${path}") || return 1
    [[ ! -e ${path} && ! -L ${path} \
        && ! -e ${temporary} && ! -L ${temporary} ]] || return 1
    if ! (umask 077; printf '%s\n' "${payload}" >"${temporary}"); then
        rm -f -- "${temporary}" || true
        return 1
    fi
    if ! chmod 0400 -- "${temporary}" \
        || ! chown root:root -- "${temporary}" \
        || ! fsync_file_and_parent "${temporary}"; then
        rm -f -- "${temporary}" || true
        return 1
    fi
    if ! ln -- "${temporary}" "${path}"; then
        rm -f -- "${temporary}" || true
        return 1
    fi
    if ! fsync_directory "${directory}"; then
        rm -f -- "${path}" "${temporary}" || true
        fsync_directory "${directory}" || true
        return 1
    fi
    if ! rm -f -- "${temporary}" || ! fsync_directory "${directory}"; then
        return 1
    fi
    metadata=$(stat -c '%u:%g:%a:%h:%F' -- "${path}") || return 1
    [[ ${metadata} == '0:0:400:1:regular file' ]]
}

read_journal_value() {
    local path=$1 key=$2 line
    while IFS= read -r line || [[ -n ${line} ]]; do
        if [[ ${line} == "${key}="* ]]; then
            printf '%s\n' "${line#*=}"
            return 0
        fi
    done <"${path}"
    return 1
}

read_payload_value() {
    local payload=$1 key=$2 line
    while IFS= read -r line; do
        if [[ ${line} == "${key}="* ]]; then
            printf '%s\n' "${line#*=}"
            return 0
        fi
    done <<<"${payload}"
    return 1
}

replace_unqualified_cleanup_receipt() {
    local path=$1 identifier=$2 payload=$3 temporary metadata
    [[ -f ${path} && ! -L ${path} ]] || return 1
    [[ $(read_journal_value "${path}" schema_version) == 2 ]] || return 1
    [[ $(read_journal_value "${path}" run_id) == "${identifier}" ]] || return 1
    [[ $(read_journal_value "${path}" cleanup) == passed ]] || return 1
    [[ $(read_journal_value "${path}" qualified_cleanup) == 0 ]] || return 1
    metadata=$(stat -c '%u:%g:%a:%h:%F' -- "${path}") || return 1
    [[ ${metadata} == '0:0:400:1:regular file' ]] || return 1

    temporary=${path}.upgrade.$$
    (umask 077; printf '%s' "${payload}" >"${temporary}") || return 1
    chmod 0400 -- "${temporary}" || return 1
    chown root:root -- "${temporary}" || return 1
    fsync_file_and_parent "${temporary}" || return 1
    if ! mv -fT -- "${temporary}" "${path}"; then
        rm -f -- "${temporary}"
        return 1
    fi
    fsync_directory "$(dirname -- "${path}")"
}

derive_run_paths() {
    local identifier=$1
    [[ ${identifier} =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]
    run_id=${identifier}
    benchmark_group=${persistent_group}/run-${run_id}
    harness_group=${benchmark_group}/harness
    workload_group=${benchmark_group}/workload
    services_group=${benchmark_group}/services
    migration_socket=${runtime_root}/cgroup-supervisor-${run_id}.sock
    runner_gate=${runtime_root}/runner-gate-${run_id}.fifo
    intent_path=${journal_root}/${run_id}.intent
    done_path=${journal_root}/${run_id}.done
    runner_success_path=${journal_root}/${run_id}.runner-success
    partial_output_publish_path=${journal_root}/${run_id}.partial-publish.output
    partial_checkpoint_publish_path=${journal_root}/${run_id}.partial-publish.checkpoint
    image_path=${image_root}/${run_id}.ext4
    output_artifact=${artifact_root}/${run_id}.output
    checkpoint_artifact=${artifact_root}/${run_id}.checkpoint
    quota_mount=${mounts_root}/${run_id}
}

create_root_artifacts() {
    [[ ! -e ${output_artifact} && ! -L ${output_artifact} \
        && ! -e ${checkpoint_artifact} && ! -L ${checkpoint_artifact} ]] || return 1
    if ! (umask 077; set -o noclobber; : >"${output_artifact}"); then
        return 1
    fi
    if ! (umask 077; set -o noclobber; : >"${checkpoint_artifact}"); then
        rm -f -- "${output_artifact}" || true
        fsync_directory "${artifact_root}" || true
        return 1
    fi
    if ! chown root:root -- "${output_artifact}" "${checkpoint_artifact}" \
        || ! chmod 0600 -- "${output_artifact}" "${checkpoint_artifact}" \
        || ! fsync_file_and_parent "${output_artifact}" \
        || ! fsync_file_and_parent "${checkpoint_artifact}"; then
        rm -f -- "${output_artifact}" "${checkpoint_artifact}" || true
        fsync_directory "${artifact_root}" || true
        return 1
    fi
    if ! exec 8<>"${output_artifact}"; then
        return 1
    fi
    runner_output_fd=8
    if ! exec 9<>"${checkpoint_artifact}"; then
        exec 8>&-
        runner_output_fd=
        return 1
    fi
    runner_checkpoint_fd=9
}

close_runner_artifact_fds() {
    if [[ -n ${runner_output_fd} ]]; then
        exec 8>&-
        runner_output_fd=
    fi
    if [[ -n ${runner_checkpoint_fd} ]]; then
        exec 9>&-
        runner_checkpoint_fd=
    fi
}

retain_unqualified_artifacts() {
    local identifier=$1 success_schema=missing
    derive_run_paths "${identifier}" || return 1
    if [[ -e ${runner_success_path} || -L ${runner_success_path} ]]; then
        [[ -f ${runner_success_path} && ! -L ${runner_success_path} ]] || return 1
        success_schema=$(read_journal_value \
            "${runner_success_path}" schema_version || true)
        if [[ ${success_schema} == 2 ]]; then
            return 0
        fi
    fi
    "${venv_python}" - "${artifact_root}" \
        "${output_artifact}" "${checkpoint_artifact}" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
artifacts = (
    (pathlib.Path(sys.argv[2]), {0o600, 0o444, 0o400}, "output"),
    (pathlib.Path(sys.argv[3]), {0o600, 0o400}, "checkpoint"),
)
if any(path.parent != root for path, _, _ in artifacts):
    raise SystemExit("unqualified artifact escaped its root")
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
directory = os.open(root, flags)
try:
    root_metadata = os.fstat(directory)
    if not (
        stat.S_ISDIR(root_metadata.st_mode)
        and root_metadata.st_uid == 0
        and root_metadata.st_gid == 0
        and stat.S_IMODE(root_metadata.st_mode) == 0o700
    ):
        raise SystemExit("artifact root is not a private root-owned directory")
    for path, allowed_modes, label in artifacts:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
        except FileNotFoundError:
            continue
        try:
            metadata = os.fstat(descriptor)
            path_metadata = os.stat(
                path.name, dir_fd=directory, follow_symlinks=False
            )
            identity = (metadata.st_dev, metadata.st_ino)
            if not (
                stat.S_ISREG(metadata.st_mode)
                and stat.S_ISREG(path_metadata.st_mode)
                and (path_metadata.st_dev, path_metadata.st_ino) == identity
                and metadata.st_uid == path_metadata.st_uid == 0
                and metadata.st_gid == path_metadata.st_gid == 0
                and metadata.st_nlink == path_metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) in allowed_modes
                and stat.S_IMODE(path_metadata.st_mode) in allowed_modes
            ):
                raise SystemExit(f"unqualified {label} artifact changed identity")
            # Preserve failed/partial evidence outside the disposable quota
            # image. It remains root-private and cannot be promoted without
            # the existing qualified producer and cleanup receipts.
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            os.fsync(directory)
        finally:
            os.close(descriptor)
finally:
    os.close(directory)
PY
}

new_run_id() {
    local candidate
    if [[ -n ${LMYZMAIL_BENCHMARK_RUN_ID:-} ]]; then
        candidate=${LMYZMAIL_BENCHMARK_RUN_ID}
    else
        candidate=$(<"${proc_root}/sys/kernel/random/uuid")
    fi
    candidate=${candidate,,}
    derive_run_paths "${candidate}"
    printf '%s\n' "${candidate}"
}

process_stat_field() {
    local pid=$1 field_index=$2 stat_line= stat_tail=
    local -a stat_fields=()
    [[ ${pid} =~ ^[1-9][0-9]*$ && -r ${proc_root}/${pid}/stat ]] || return 1
    IFS= read -r stat_line <"${proc_root}/${pid}/stat" || return 1
    stat_tail=${stat_line##*) }
    read -r -a stat_fields <<<"${stat_tail}"
    (( ${#stat_fields[@]} > field_index )) || return 1
    [[ ${stat_fields[field_index]} =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "${stat_fields[field_index]}"
}

process_start_time() {
    process_stat_field "$1" 19
}

process_group_id() {
    process_stat_field "$1" 2
}

pid_in_benchmark_cgroup() {
    local pid=$1 hierarchy= controllers= path= benchmark_path=
    [[ -n ${benchmark_group} && ${benchmark_group} == "${persistent_group}/"* \
        && -r ${proc_root}/${pid}/cgroup ]] || return 1
    benchmark_path=${benchmark_group#"${cgroup_root}"}
    while IFS=: read -r hierarchy controllers path; do
        [[ ${hierarchy} == 0 && -z ${controllers} ]] || continue
        [[ ${path} == "${benchmark_path}" || ${path} == "${benchmark_path}/"* ]]
        return
    done <"${proc_root}/${pid}/cgroup"
    return 1
}

registered_runner_matches() {
    local pid=$1 expected_start_time=$2 actual_start_time=
    actual_start_time=$(process_start_time "${pid}") || return 1
    [[ ${actual_start_time} == "${expected_start_time}" ]] \
        && pid_in_benchmark_cgroup "${pid}"
}

try_write_runner_gate() {
    local pid=$1 expected_start_time=$2
    "${venv_python}" - \
        "${runner_gate}" "${proc_root}" "${pid}" "${expected_start_time}" <<'PY'
import errno
import os
import pathlib
import stat
import sys

gate = pathlib.Path(sys.argv[1])
proc_root = pathlib.Path(sys.argv[2])
pid = int(sys.argv[3])
expected_start_time = int(sys.argv[4])


def runner_start_time_matches():
    try:
        raw = (proc_root / str(pid) / "stat").read_text(encoding="ascii")
        tail = raw.rsplit(") ", 1)[1].split()
        return len(tail) > 19 and int(tail[19]) == expected_start_time
    except (FileNotFoundError, IndexError, OSError, ValueError):
        return False


if not runner_start_time_matches():
    raise SystemExit(76)
before = gate.lstat()
if (
    not stat.S_ISFIFO(before.st_mode)
    or stat.S_IMODE(before.st_mode) != 0o600
    or before.st_uid != 0
    or before.st_gid != 0
    or before.st_nlink != 1
):
    raise SystemExit("runner gate metadata is invalid")
flags = os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
try:
    descriptor = os.open(gate, flags)
except OSError as error:
    if error.errno in (errno.ENXIO, errno.EAGAIN, errno.EWOULDBLOCK):
        raise SystemExit(75) from None
    raise
try:
    opened = os.fstat(descriptor)
    current = gate.lstat()
    identity = (before.st_dev, before.st_ino)
    if (
        not runner_start_time_matches()
        or (opened.st_dev, opened.st_ino) != identity
        or (current.st_dev, current.st_ino) != identity
        or not stat.S_ISFIFO(opened.st_mode)
    ):
        raise SystemExit(76)
    if os.write(descriptor, b"GO\n") != 3:
        raise SystemExit("runner gate write was incomplete")
finally:
    os.close(descriptor)
PY
}

release_registered_runner_gate() {
    local pid=$1 expected_start_time=$2 deadline attempt_status
    deadline=$((SECONDS + runner_gate_timeout_seconds))
    while (( SECONDS < deadline )); do
        if ! registered_runner_matches "${pid}" "${expected_start_time}"; then
            echo "benchmark runner exited before the gate rendezvous" >&2
            return 1
        fi
        if try_write_runner_gate "${pid}" "${expected_start_time}"; then
            return 0
        else
            attempt_status=$?
        fi
        if (( attempt_status != 75 )); then
            echo "benchmark runner identity changed before the gate rendezvous" >&2
            return 1
        fi
        if ! registered_runner_matches "${pid}" "${expected_start_time}"; then
            echo "benchmark runner exited before opening the gate" >&2
            return 1
        fi
        sleep 0.05
    done
    echo "benchmark runner did not open its gate before the deadline" >&2
    return 1
}

signal_registered_runner() {
    local pid=$1 expected_start_time=$2 signal_name=$3 process_group=
    if ! registered_runner_matches "${pid}" "${expected_start_time}"; then
        echo "benchmark watchdog refused to signal a stale or out-of-cgroup runner PID" >&2
        return 1
    fi
    process_group=$(process_group_id "${pid}") || return 1
    if [[ ${process_group} == "${pid}" ]] \
        && registered_runner_matches "${pid}" "${expected_start_time}" \
        && kill "-${signal_name}" -- "-${pid}" 2>/dev/null; then
        return 0
    fi
    registered_runner_matches "${pid}" "${expected_start_time}" \
        && kill "-${signal_name}" -- "${pid}" 2>/dev/null
}

cgroup_has_members() {
    local group=$1 pid=
    [[ -n ${group} && -r ${group}/cgroup.procs ]] || return 1
    read -r pid <"${group}/cgroup.procs" || true
    [[ -n ${pid} ]]
}

benchmark_cgroups_are_empty() {
    ! cgroup_has_members "${workload_group}" \
        && ! cgroup_has_members "${services_group}" \
        && ! cgroup_has_members "${harness_group}" \
        && ! cgroup_has_members "${benchmark_group}"
}

wait_for_cgroup_unpopulated() {
    local group=$1 timeout_seconds=$2 deadline populated=
    deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
        if [[ ! -d ${group} ]]; then
            return 0
        fi
        populated=$(awk '$1 == "populated" {print $2}' "${group}/cgroup.events" 2>/dev/null || true)
        if [[ ${populated} == 0 ]]; then
            return 0
        fi
        sleep 0.05
    done
    [[ ! -d ${group} ]] || grep -qx 'populated 0' "${group}/cgroup.events"
}

signal_benchmark_members() {
    local signal_name=$1 group pid
    for group in "${workload_group}" "${services_group}" \
        "${harness_group}" "${benchmark_group}"; do
        [[ -r ${group}/cgroup.procs ]] || continue
        while read -r pid; do
            [[ -n ${pid} && ${pid} != $$ && ${pid} != "${BASHPID}" ]] \
                && pid_in_benchmark_cgroup "${pid}" \
                && kill "-${signal_name}" -- "${pid}" 2>/dev/null || true
        done <"${group}/cgroup.procs"
    done
}

bounded_member_sweep() {
    local signal_name=$1 timeout_seconds=$2 deadline
    deadline=$((SECONDS + timeout_seconds))
    while ! benchmark_cgroups_are_empty; do
        signal_benchmark_members "${signal_name}"
        (( SECONDS < deadline )) || break
        sleep 0.05
    done
    benchmark_cgroups_are_empty
}

terminate_members() {
    bounded_member_sweep TERM 10 && return 0
    bounded_member_sweep KILL 5 && return 0
    echo "benchmark cgroups retained processes after SIGKILL" >&2
    return 1
}

kill_benchmark_cgroup() {
    [[ -n ${benchmark_group} && ${benchmark_group} != "${cgroup_root}" \
        && ${benchmark_group} == "${persistent_group}/run-"* \
        && -w ${benchmark_group}/cgroup.kill ]] || return 1
    pid_in_benchmark_cgroup "${BASHPID}" && return 1
    printf '1\n' >"${benchmark_group}/cgroup.kill" || return 1
    wait_for_cgroup_unpopulated "${benchmark_group}" 10
}

loop_devices_for_image() {
    local image=$1
    losetup -j "${image}" --output NAME --noheadings 2>/dev/null \
        | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
        | grep -E '^/dev/loop[0-9]+$' || true
}

mount_is_active() {
    findmnt -rn -M "$1" >/dev/null 2>&1
}

cleanup_run_resources() {
    local identifier=$1 allow_lazy=$2 cleanup_failed=0 group device
    derive_run_paths "${identifier}" || return 1
    cleanup_lazy_used=0

    if [[ -d ${benchmark_group} ]]; then
        if ! kill_benchmark_cgroup; then
            terminate_members || cleanup_failed=1
        fi
        if ! wait_for_cgroup_unpopulated "${benchmark_group}" 10; then
            echo "benchmark cgroup remained populated during cleanup" >&2
            cleanup_failed=1
        fi
    fi

    if mount_is_active "${quota_mount}"; then
        if ! umount -- "${quota_mount}"; then
            if [[ ${allow_lazy} == 1 ]] && umount -l -- "${quota_mount}"; then
                cleanup_lazy_used=1
            else
                echo "benchmark quota mount could not be unmounted: ${quota_mount}" >&2
                cleanup_failed=1
            fi
        fi
    fi

    while IFS= read -r device; do
        [[ -n ${device} ]] || continue
        # util-linux losetup 2.39 treats a standalone `--` as the device name.
        # `device` is already constrained to ^/dev/loop[0-9]+$ above.
        if ! losetup -d "${device}"; then
            echo "benchmark loop device could not be detached: ${device}" >&2
            cleanup_failed=1
        fi
    done < <(loop_devices_for_image "${image_path}")

    if [[ -e ${image_path} || -L ${image_path} ]]; then
        if ! rm -f -- "${image_path}"; then
            echo "benchmark backing image could not be removed: ${image_path}" >&2
            cleanup_failed=1
        fi
    fi

    for group in "${workload_group}" "${services_group}" \
        "${harness_group}" "${benchmark_group}"; do
        if [[ -d ${group} ]] && ! rmdir -- "${group}"; then
            echo "benchmark cgroup could not be removed: ${group}" >&2
            cleanup_failed=1
        fi
    done
    if [[ -d ${quota_mount} ]] && ! rmdir -- "${quota_mount}"; then
        echo "benchmark mount directory could not be removed: ${quota_mount}" >&2
        cleanup_failed=1
    fi
    if [[ -e ${migration_socket} || -L ${migration_socket} ]]; then
        if ! rm -f -- "${migration_socket}"; then
            echo "benchmark cgroup supervisor socket could not be removed" >&2
            cleanup_failed=1
        fi
    fi
    if [[ -e ${runner_gate} || -L ${runner_gate} ]]; then
        if ! rm -f -- "${runner_gate}"; then
            echo "benchmark runner gate could not be removed" >&2
            cleanup_failed=1
        fi
    fi
    return "${cleanup_failed}"
}

validate_historical_unqualified_cleanup_receipt() {
    local path=$1 identifier=$2 metadata request lazy recovered checkpoint
    [[ -f ${path} && ! -L ${path} ]] || return 1
    metadata=$(stat -c '%u:%g:%a:%h:%F' -- "${path}") || return 1
    [[ ${metadata} == '0:0:400:1:regular file' ]] || return 1
    [[ $(read_journal_value "${path}" schema_version) == 3 ]] || return 1
    [[ $(read_journal_value "${path}" run_id) == "${identifier}" ]] || return 1
    request=$(read_journal_value "${path}" request) || return 1
    [[ ${request} == ABORT || ${request} == RECOVERY ]] || return 1
    [[ $(read_journal_value "${path}" cleanup) == passed ]] || return 1
    lazy=$(read_journal_value "${path}" lazy_unmount) || return 1
    recovered=$(read_journal_value "${path}" recovered) || return 1
    [[ ${lazy} == 0 || ${lazy} == 1 ]] || return 1
    [[ ${recovered} == 0 || ${recovered} == 1 ]] || return 1
    [[ $(read_journal_value "${path}" qualified_cleanup) == 0 ]] || return 1
    [[ $(read_journal_value "${path}" provisional_sha256) == missing ]] || return 1
    checkpoint=$(read_journal_value "${path}" checkpoint_sha256 || true)
    [[ -z ${checkpoint} || ${checkpoint} == missing ]]
}

write_cleanup_receipt() {
    local identifier=$1 request=$2 lazy=$3 recovered=$4
    local expected_pid=${5:-} expected_start_time=${6:-}
    local qualified=0 provisional_sha=missing checkpoint_sha=missing
    local payload existing_schema existing_qualified success_schema=missing
    derive_run_paths "${identifier}" || return 1
    if [[ -f ${runner_success_path} ]]; then
        success_schema=$(read_journal_value "${runner_success_path}" schema_version || true)
        provisional_sha=$(read_journal_value "${runner_success_path}" provisional_sha256 || true)
        checkpoint_sha=$(read_journal_value "${runner_success_path}" checkpoint_sha256 || true)
    fi
    if [[ ${success_schema} == 2 && ${lazy} == 0 \
        && ( ${request} == DONE || ${request} == RECOVERY ) ]] \
        && validate_runner_success \
            "${identifier}" "${expected_pid}" "${expected_start_time}"; then
        qualified=1
    fi
    payload=$(printf '%s\n' \
        'schema_version=2' \
        "run_id=${identifier}" \
        "request=${request}" \
        'cleanup=passed' \
        "lazy_unmount=${lazy}" \
        "recovered=${recovered}" \
        "qualified_cleanup=${qualified}" \
        "provisional_sha256=${provisional_sha}" \
        "checkpoint_sha256=${checkpoint_sha}") || return 1
    if [[ -e ${done_path} || -L ${done_path} ]]; then
        [[ -f ${done_path} && ! -L ${done_path} ]] || return 1
        existing_schema=$(read_journal_value "${done_path}" schema_version) || return 1
        if [[ ${existing_schema} == 3 ]]; then
            validate_historical_unqualified_cleanup_receipt \
                "${done_path}" "${identifier}" || return 1
            (( qualified == 0 ))
            return
        fi
        [[ ${existing_schema} == 2 ]] || return 1
        [[ $(read_journal_value "${done_path}" run_id) == "${identifier}" ]] || return 1
        [[ $(read_journal_value "${done_path}" cleanup) == passed ]] || return 1
        existing_qualified=$(read_journal_value "${done_path}" qualified_cleanup) || return 1
        if [[ ${existing_qualified} == 1 ]]; then
            [[ $(read_journal_value "${done_path}" lazy_unmount) == 0 ]] || return 1
            [[ $(read_journal_value "${done_path}" provisional_sha256) == "${provisional_sha}" ]] \
                || return 1
            [[ $(read_journal_value "${done_path}" checkpoint_sha256) == "${checkpoint_sha}" ]] \
                || return 1
            return 0
        fi
        [[ ${existing_qualified} == 0 ]] || return 1
        if (( qualified != 0 )); then
            replace_unqualified_cleanup_receipt \
                "${done_path}" "${identifier}" "${payload}" || return 1
        fi
        return 0
    fi
    write_journal_once "${done_path}" "${payload}"
}

inspect_runner_artifacts() {
    local mode=$1 output=$2 checkpoint=$3 logical_output=$4 identifier=$5 formal=$6
    local expected_rust_fsync=$7 expected_output_sha=${8:-}
    local expected_output_device=${9:-} expected_output_inode=${10:-}
    local expected_output_size=${11:-} expected_checkpoint_sha=${12:-}
    local expected_checkpoint_device=${13:-} expected_checkpoint_inode=${14:-}
    local expected_checkpoint_size=${15:-}
    "${venv_python}" - "${mode}" "${output}" "${checkpoint}" \
        "${logical_output}" "${repository}" "${identifier}" "${formal}" \
        "${benchmark_uid}" "${benchmark_gid}" "${expected_rust_fsync}" \
        "${expected_output_sha}" "${expected_output_device}" \
        "${expected_output_inode}" "${expected_output_size}" \
        "${expected_checkpoint_sha}" "${expected_checkpoint_device}" \
        "${expected_checkpoint_inode}" "${expected_checkpoint_size}" <<'PY'
import hashlib
import json
import math
import os
import pathlib
import stat
import sys
import uuid

(
    mode,
    output_raw,
    checkpoint_raw,
    logical_output_raw,
    repository_raw,
    launcher_run_id,
    formal_raw,
    benchmark_uid_raw,
    benchmark_gid_raw,
    expected_rust_fsync,
    expected_output_sha,
    expected_output_device_raw,
    expected_output_inode_raw,
    expected_output_size_raw,
    expected_checkpoint_sha,
    expected_checkpoint_device_raw,
    expected_checkpoint_inode_raw,
    expected_checkpoint_size_raw,
) = sys.argv[1:]
formal = formal_raw == "1"
if mode not in {"promote", "validate"} or formal_raw not in {"0", "1"}:
    raise SystemExit("artifact inspection mode is invalid")
if expected_rust_fsync not in {"on", "off", "not-applicable"}:
    raise SystemExit("expected Rust filesystem fsync mode is invalid")
expected_rust_fsync_value = (
    None if expected_rust_fsync == "not-applicable" else expected_rust_fsync
)
try:
    parsed_launcher_run_id = uuid.UUID(launcher_run_id)
except ValueError as error:
    raise SystemExit("launcher run identity is invalid") from error
if parsed_launcher_run_id.version != 4 or str(parsed_launcher_run_id) != launcher_run_id:
    raise SystemExit("launcher run identity is not canonical UUIDv4")

repository = pathlib.Path(repository_raw).resolve()
logical_output = pathlib.Path(logical_output_raw).resolve(strict=False)
try:
    logical_relative = logical_output.relative_to(repository).as_posix()
except ValueError as error:
    raise SystemExit("logical output escaped the repository") from error


def parse_expected(raw, name):
    if mode == "promote":
        if raw:
            raise SystemExit(f"unexpected {name} in promote mode")
        return None
    try:
        value = int(raw)
    except ValueError as error:
        raise SystemExit(f"invalid expected {name}") from error
    if value < 0:
        raise SystemExit(f"negative expected {name}")
    return value


expected_output_device = parse_expected(expected_output_device_raw, "output device")
expected_output_inode = parse_expected(expected_output_inode_raw, "output inode")
expected_output_size = parse_expected(expected_output_size_raw, "output size")
expected_checkpoint_device = parse_expected(
    expected_checkpoint_device_raw, "checkpoint device"
)
expected_checkpoint_inode = parse_expected(
    expected_checkpoint_inode_raw, "checkpoint inode"
)
expected_checkpoint_size = parse_expected(expected_checkpoint_size_raw, "checkpoint size")
if mode == "validate":
    for digest in (expected_output_sha, expected_checkpoint_sha):
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise SystemExit("expected artifact SHA-256 is invalid")


def read_bounded(descriptor, maximum, label):
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = bytearray()
    while len(payload) <= maximum:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) > maximum:
        raise SystemExit(f"{label} exceeds its size bound")
    return bytes(payload)


def open_artifact(path_raw, label, expected_mode, expected_device, expected_inode, expected_size):
    path = pathlib.Path(path_raw)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    path_metadata = path.lstat()
    identity = (metadata.st_dev, metadata.st_ino)
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} is not a regular file")
    if (path_metadata.st_dev, path_metadata.st_ino) != identity:
        raise SystemExit(f"{label} path changed after open")
    if mode == "promote":
        if metadata.st_nlink != 1:
            raise SystemExit(f"{label} is multiply linked before promotion")
        if metadata.st_uid != 0 or metadata.st_gid != 0:
            raise SystemExit(f"{label} is not root-owned before promotion")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise SystemExit(f"{label} has unexpected pre-promotion mode")
    else:
        if metadata.st_nlink not in (1, 2):
            raise SystemExit(f"{label} has invalid root-owned link count")
        if metadata.st_uid != 0 or metadata.st_gid != 0:
            raise SystemExit(f"{label} is not root-owned")
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise SystemExit(f"{label} has invalid root-owned mode")
        if identity != (expected_device, expected_inode) or metadata.st_size != expected_size:
            raise SystemExit(f"{label} identity differs from the runner receipt")
    return path, descriptor, metadata, identity


def canonical_uuid4(value, label):
    if not isinstance(value, str):
        raise SystemExit(f"{label} is missing")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise SystemExit(f"{label} is invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise SystemExit(f"{label} is not canonical UUIDv4")
    return value


def valid_sha256(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and not any(character not in "0123456789abcdef" for character in value)
    )


def valid_dkim_fixture(value):
    return bool(
        isinstance(value, dict)
        and value.get("profile") == "lmyzmail-ephemeral-dkim-signing-fixture-v1"
        and value.get("relative_path") == "benchmark-fixtures/dkim-private.pem"
        and value.get("selector") == "mail"
        and value.get("algorithm") == "rsa-sha256"
        and value.get("key_bits") == 2048
        and value.get("private_key_format") == "pkcs8-pem"
        and isinstance(value.get("private_key_bytes"), int)
        and 1024 <= value["private_key_bytes"] <= 32 * 1024
        and valid_sha256(value.get("private_key_sha256"))
        and valid_sha256(value.get("public_key_spki_sha256"))
        and value.get("directory_mode") == "0700"
        and value.get("file_mode") == "0600"
        and isinstance(value.get("owner_uid"), int)
        and value["owner_uid"] > 0
        and isinstance(value.get("owner_gid"), int)
        and value["owner_gid"] > 0
        and value.get("hard_link_count") == 1
        and value.get("inside_quota_workspace") is True
        and value.get("production_secret_used") is False
        and value.get("passed") is True
    )


def valid_application_persistence_io(arm, resource):
    if not isinstance(arm, dict) or not isinstance(resource, dict):
        return False
    if resource.get("application_persistence_io_observed") is True:
        return True
    sources = resource.get("application_persistence_io_sources")
    return bool(
        arm.get("target") == "rust-candidate"
        and expected_rust_fsync_value == "off"
        and isinstance(sources, dict)
        and sources.get("process_observed") is True
        and sources.get("observed") is True
    )


def validate_output(payload):
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit("provisional evidence is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise SystemExit("provisional evidence root is not an object")
    if value.get("schema_version") != 1:
        raise SystemExit("provisional evidence schema changed")
    profile = value.get("profile")
    java_small = profile == "java-small-single-invocation-smtp-endpoint-baseline-v1"
    legacy_candidate_stability = (
        profile == "rust-candidate-single-invocation-smtp-endpoint-stability-v1"
    )
    continuation_candidate_stability = (
        profile == "rust-candidate-continuation-smtp-endpoint-stability-v2"
    )
    candidate_stability = (
        legacy_candidate_stability or continuation_candidate_stability
    )
    legacy_abba = profile == "abba-single-invocation-smtp-endpoint-throughput-v1"
    mixed_v2 = profile == "mixed-single-invocation-smtp-endpoint-throughput-v2"
    if profile not in {
        "abba-single-invocation-smtp-endpoint-throughput-v1",
        "mixed-single-invocation-smtp-endpoint-throughput-v2",
        "java-small-single-invocation-smtp-endpoint-baseline-v1",
        "rust-candidate-single-invocation-smtp-endpoint-stability-v1",
        "rust-candidate-continuation-smtp-endpoint-stability-v2",
    }:
        raise SystemExit("provisional evidence profile changed")
    if value.get("launcher_run_id") != launcher_run_id:
        raise SystemExit("provisional evidence launcher identity changed")
    runner_run_id = canonical_uuid4(value.get("run_id"), "runner run identity")
    attestation = value.get("attestation")
    methodology = value.get("methodology")
    rows = value.get("rows")
    if not (
        value.get("rust_filesystem_fsync") == expected_rust_fsync_value
        and isinstance(attestation, dict)
        and attestation.get("rust_filesystem_fsync") == expected_rust_fsync_value
        and isinstance(methodology, dict)
        and methodology.get("rust_filesystem_fsync") == expected_rust_fsync_value
        and methodology.get("one_rust_filesystem_fsync_mode_per_evidence_file")
        is True
        and isinstance(rows, list)
    ):
        raise SystemExit("Rust filesystem fsync provenance changed")
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("arms"), list):
            raise SystemExit("benchmark row arm vector is invalid")
        arm_mode = (
            expected_rust_fsync_value
            if row.get("target") == "rust-candidate"
            else None
        )
        if any(arm.get("rust_filesystem_fsync") != arm_mode for arm in row["arms"]):
            raise SystemExit("benchmark arm mixed Rust filesystem fsync modes")
    if value.get("status") != "passed":
        raise SystemExit("provisional benchmark did not pass")
    qualified = value.get("qualified")
    if not isinstance(qualified, bool):
        raise SystemExit("provisional qualification is not boolean")
    if not (
        (
            continuation_candidate_stability
            and value.get("endpoint_invocations")
            == value.get("total_endpoint_invocations")
            and value.get("endpoint_invocation_scope") == "run"
        )
        or (
            not continuation_candidate_stability
            and value.get("endpoint_invocations") == 1
            and value.get("endpoint_invocation_scope") == "per_arm"
        )
    ) or not (
        value.get("harness_batches") == 0
        and value.get("endpoint_requested_messages_match_observer_verified") is True
    ):
        raise SystemExit("provisional top-level no-batching contract changed")
    if java_small:
        expected_plans = [
            {"label": "1KB", "message_bytes": 1024, "total_messages": 200_000},
            {"label": "10KB", "message_bytes": 10 * 1024, "total_messages": 200_000},
        ]
        expected_order = [
            {"target": "java-oracle", "tier": plan["label"], "arm_ordinal": 0}
            for plan in expected_plans
        ]
        comparison = value.get("comparison")
        acceptance = value.get("acceptance")
        methodology = value.get("methodology")
        rows = value.get("rows")
        if not (
            formal is False
            and qualified is False
            and value.get("qualification_prerequisites_passed") is False
            and value.get("plans") == expected_plans
            and value.get("execution_order") == expected_order
            and value.get("total_endpoint_invocations") == 2
            and value.get("endpoint_requested_messages") == [200_000, 200_000]
            and value.get("observer_verified_messages") == [200_000, 200_000]
        ):
            raise SystemExit("Java-small top-level contract changed")
        if not isinstance(comparison, dict) or not all(
            comparison.get(key) is True
            for key in (
                "all_passed",
                "baseline_complete_passed",
                "plan_order_passed",
                "operational_evidence_passed",
                "zero_retry_gate_passed",
                "java_only_passed",
                "single_arm_per_tier_passed",
                "ten_megabyte_excluded",
            )
        ):
            raise SystemExit("Java-small comparison gates did not all pass")
        comparison_rows = comparison.get("comparisons")
        if not isinstance(comparison_rows, list) or not all(
            isinstance(row, dict) for row in comparison_rows
        ) or [
            {
                "tier": row.get("tier"),
                "target": row.get("target"),
                "requested_messages": row.get("requested_messages"),
                "observer_verified_messages": row.get("observer_verified_messages"),
                "single_endpoint_invocation": row.get("single_endpoint_invocation"),
                "queue_scheduler_observed": row.get("queue_scheduler_observed"),
                "passed": row.get("passed"),
            }
            for row in comparison_rows
        ] != [
            {
                "tier": plan["label"],
                "target": "java-oracle",
                "requested_messages": 200_000,
                "observer_verified_messages": 200_000,
                "single_endpoint_invocation": True,
                "queue_scheduler_observed": True,
                "passed": True,
            }
            for plan in expected_plans
        ]:
            raise SystemExit("Java-small tier summaries changed")
        if not isinstance(acceptance, dict) or not (
            acceptance.get("passed") is True
            and acceptance.get("qualified") is False
            and acceptance.get("no_batching") is True
            and acceptance.get("java_small_baseline") is True
            and acceptance.get("java_only") is True
            and acceptance.get("one_arm_per_tier") is True
            and acceptance.get("one_endpoint_invocation_per_tier") is True
            and acceptance.get("one_kib_then_ten_kib") is True
            and acceptance.get("two_hundred_thousand_messages_per_tier") is True
            and acceptance.get("ten_megabyte_excluded") is True
            and acceptance.get("not_qualification_evidence") is True
            and acceptance.get("no_warmup_endpoint_calls") is True
            and acceptance.get("no_repetition_loop") is True
            and acceptance.get("no_stress_start_retries") is True
        ):
            raise SystemExit("Java-small acceptance semantics changed")
        if not isinstance(methodology, dict) or not (
            methodology.get("per_tier_order") == "1KB then 10KB"
            and methodology.get("per_tier_arms") == ["java-oracle"]
            and methodology.get("one_large_start_invocation_per_arm") is True
            and methodology.get("harness_batching") is False
            and methodology.get("automatic_endpoint_cleanup_only") is True
            and methodology.get("warmup_endpoint_invocations") == 0
            and methodology.get("repetition_loop") is False
            and methodology.get("single_logical_cpu_for_application") is True
            and methodology.get("io_limit_bytes_per_second_read_and_write") == 500_000_000
            and methodology.get("hard_disk_budget_bytes") == 20 * 1024**3
            and methodology.get("performance_gate_uses_both_ordinal_pairs") is False
            and methodology.get("performance_gate_uses_min_rust_over_max_java") is False
            and methodology.get("java_small_baseline_is_not_qualification_evidence") is True
        ):
            raise SystemExit("Java-small methodology semantics changed")
        java_profile = methodology.get("java_stress_runtime_profile")
        dkim_profile = (
            java_profile.get("dkim_signing_fixture")
            if isinstance(java_profile, dict)
            else None
        )
        if not (
            isinstance(java_profile, dict)
            and java_profile.get("profile")
            == "java-oracle-frozen-production-stress-path-v1"
            and java_profile.get("source_path")
            == "evidence/freeze/java-oracle/application.properties.redacted"
            and java_profile.get("source_sha256")
            == "350effbab18151cf78d5e850ee22d8d22569b30e2f38b18b281b7a8b50be3394"
            and dkim_profile
            == {
                "provisioning": "fresh-per-isolated-arm",
                "algorithm": "rsa-sha256",
                "key_bits": 2048,
                "private_key_format": "pkcs8-pem",
                "selector": "mail",
                "relative_path": "benchmark-fixtures/dkim-private.pem",
                "directory_mode": "0700",
                "file_mode": "0600",
                "production_secret_used": False,
            }
            and java_profile.get("forbidden_measurement_log_prefixes")
            == [
                "No DKIM configuration for domain:",
                "Async drop: email rejected after verification:",
            ]
        ):
            raise SystemExit("Java-small DKIM runtime profile changed")
        if not isinstance(rows, list) or len(rows) != 2:
            raise SystemExit("Java-small rows are missing")
        dns_fixture = value.get("dns_fixture")
        dns_dkim = dns_fixture.get("dkim") if isinstance(dns_fixture, dict) else None
        if not (
            isinstance(dns_fixture, dict)
            and dns_fixture.get("profile") == "lmyzmail-smtp-benchmark-dns-v1"
            and dns_fixture.get("spf_record") == "v=spf1 +all"
            and dns_fixture.get("dmarc_record")
            == "v=DMARC1; p=none; adkim=s; aspf=s"
            and dns_fixture.get("passed") is True
            and dns_fixture.get("dkim_txt_query_count", 0) >= 2
            and dns_fixture.get("dmarc_txt_query_count", 0) >= 2
            and isinstance(dns_dkim, dict)
            and dns_dkim.get("profile")
            == "lmyzmail-shared-ephemeral-dkim-material-v1"
            and dns_dkim.get("dns_name") == "mail._domainkey.lmyz.net"
            and dns_dkim.get("selector") == "mail"
            and dns_dkim.get("domain") == "lmyz.net"
            and dns_dkim.get("key_bits") == 2048
            and valid_sha256(dns_dkim.get("private_key_sha256"))
            and valid_sha256(dns_dkim.get("public_key_spki_sha256"))
            and valid_sha256(dns_dkim.get("public_dns_record_sha256"))
            and dns_dkim.get("production_secret_used") is False
            and dns_dkim.get("passed") is True
        ):
            raise SystemExit("Java-small authentication DNS evidence changed")
        for plan, row in zip(expected_plans, rows, strict=True):
            arms = row.get("arms") if isinstance(row, dict) else None
            measurements = row.get("measurements") if isinstance(row, dict) else None
            if not (
                isinstance(row, dict)
                and row.get("target") == "java-oracle"
                and row.get("tier") == plan
                and row.get("arm_count") == 1
                and row.get("endpoint_start_invocations") == 1
                and row.get("endpoint_invocations") == 1
                and row.get("harness_batches") == 0
                and row.get("requested_equals_observer_verified") is True
                and isinstance(arms, list)
                and len(arms) == 1
                and isinstance(measurements, list)
                and len(measurements) == 1
            ):
                raise SystemExit("Java-small row shape changed")
            arm = arms[0]
            measurement = arm.get("measurement")
            outcome = measurement.get("endpoint_outcome") if isinstance(measurement, dict) else None
            resource = measurement.get("resource") if isinstance(measurement, dict) else None
            application_log = (
                measurement.get("application_log") if isinstance(measurement, dict) else None
            )
            if not (
                arm.get("target") == "java-oracle"
                and arm.get("arm_ordinal") == 0
                and arm.get("endpoint_start_invocations") == 1
                and arm.get("endpoint_invocations") == 1
                and arm.get("harness_batches") == 0
                and arm.get("endpoint_requested_messages") == 200_000
                and arm.get("observer_verified_messages") == 200_000
                and arm.get("requested_equals_observer_verified") is True
                and valid_dkim_fixture(arm.get("dkim_fixture"))
                and arm.get("dkim_fixture", {}).get("private_key_sha256")
                == dns_dkim.get("private_key_sha256")
                and arm.get("dkim_fixture", {}).get("public_key_spki_sha256")
                == dns_dkim.get("public_key_spki_sha256")
                and isinstance(outcome, dict)
                and outcome.get("failure_count") == 0
                and outcome.get("retry_count") == 0
                and outcome.get("queue_scheduler_observed") is True
                and isinstance(application_log, dict)
                and application_log.get("missing_dkim_configuration_line_count") == 0
                and application_log.get("missing_dkim_configuration_lines") == []
                and application_log.get("async_drop_line_count") == 0
                and application_log.get("async_drop_lines") == []
                and measurement.get("endpoint_start_invocation_count") == 1
                and measurement.get("endpoint_start_automatic_retries") == 0
                and measurement.get("smtp", {}).get(
                    "within_arm_throughput_stability", {}
                ).get("passed") is True
                and isinstance(resource, dict)
                and resource.get("candidate_cpu_usage_seconds", 0) > 0
                and resource.get("services_cpu_usage_seconds", 0) > 0
                and resource.get("application_persistence_io_observed") is True
                and resource.get("services_persistence_io_observed") is True
                and resource.get("temperature", {}).get("within_limit") is True
            ):
                raise SystemExit("Java-small single-call evidence changed")
        attestation = value.get("attestation")
        external = value.get("external_prerequisites")
        calibration = value.get("real_gate_calibration")
        if not (
            isinstance(attestation, dict)
            and isinstance(external, dict)
            and external.get("provided") is False
            and external.get("passed") is False
            and isinstance(calibration, dict)
            and calibration.get("required_for_qualification") is False
            and calibration.get("performed") is False
        ):
            raise SystemExit("Java-small provenance mode changed")
        runner_sha = attestation.get("runner_sha256")
        launcher_sha = attestation.get("launcher_sha256")
        definition = attestation.get("benchmark_definition")
        definition_sha = definition.get("sha256") if isinstance(definition, dict) else None
        for digest in (runner_sha, launcher_sha, definition_sha):
            if not valid_sha256(digest):
                raise SystemExit("Java-small provenance digest is invalid")
        return value, runner_run_id, profile, runner_sha, launcher_sha, definition_sha
    if candidate_stability:
        plans = value.get("plans")
        expected_by_label = (
            {
                "1KB": {
                    "label": "1KB",
                    "message_bytes": 1024,
                    "total_messages": (
                        500_000 if legacy_candidate_stability else 250_000
                    ),
                },
                "10KB": {
                    "label": "10KB",
                    "message_bytes": 10 * 1024,
                    "total_messages": (
                        500_000 if legacy_candidate_stability else 250_000
                    ),
                },
                "10MB": {"label": "10MB", "message_bytes": 10 * 1024 * 1024, "total_messages": 500},
            }
            if formal
            else {
                "1KB": {"label": "1KB", "message_bytes": 1024, "total_messages": 8},
                "10KB": {"label": "10KB", "message_bytes": 10 * 1024, "total_messages": 8},
                "10MB": {"label": "10MB", "message_bytes": 10 * 1024 * 1024, "total_messages": 2},
            }
        )
        labels = [plan.get("label") for plan in plans] if isinstance(plans, list) else []
        expected_ordered_labels = [
            label for label in ("1KB", "10KB", "10MB") if label in labels
        ]
        if not (
            labels
            and labels == expected_ordered_labels
            and len(labels) == len(set(labels))
            and plans == [expected_by_label[label] for label in labels]
        ):
            raise SystemExit("candidate stability plan contract changed")
        expected_order = [
            {"target": "rust-candidate", "tier": label, "arm_ordinal": 0}
            for label in labels
        ]
        expected_counts = [expected_by_label[label]["total_messages"] for label in labels]
        expected_continuations = [
            100_000
            if continuation_candidate_stability
            and formal
            and label in {"1KB", "10KB"}
            else 0
            for label in labels
        ]
        expected_total_counts = [
            count + continuation
            for count, continuation in zip(
                expected_counts, expected_continuations, strict=True
            )
        ]
        expected_invocations = [
            2 if continuation else 1 for continuation in expected_continuations
        ]
        if not (
            value.get("execution_order") == expected_order
            and value.get("total_endpoint_invocations")
            == (
                sum(expected_invocations)
                if continuation_candidate_stability
                else len(labels)
            )
            and value.get("endpoint_invocations")
            == (sum(expected_invocations) if continuation_candidate_stability else 1)
            and value.get("endpoint_invocation_scope")
            == ("run" if continuation_candidate_stability else "per_arm")
            and value.get("endpoint_requested_messages") == expected_counts
            and value.get("observer_verified_messages") == expected_counts
            and (
                not continuation_candidate_stability
                or (
                    value.get("total_endpoint_requested_messages")
                    == expected_total_counts
                    and value.get("total_observer_verified_messages")
                    == expected_total_counts
                )
            )
        ):
            raise SystemExit("candidate stability top-level contract changed")
        comparison = value.get("comparison")
        required_comparison_gates = (
            "all_passed",
            "candidate_complete_passed",
            "plan_order_passed",
            "candidate_only_passed",
            "single_arm_per_tier_passed",
            "operational_evidence_passed",
            "arm_completeness_passed",
            "measurement_evidence_passed",
            "within_arm_stability_passed",
            "zero_retry_gate_passed",
            "proxy_headroom_passed",
            "java_comparison_intentionally_external",
        ) + (("same_process_continuation_passed",) if continuation_candidate_stability else ())
        if not isinstance(comparison, dict) or not all(
            comparison.get(key) is True for key in required_comparison_gates
        ):
            raise SystemExit("candidate stability comparison gates did not all pass")
        summaries = comparison.get("comparisons")
        if not isinstance(summaries, list) or len(summaries) != len(labels):
            raise SystemExit("candidate stability tier summaries changed")
        for label, continuation_count, row in zip(
            labels, expected_continuations, summaries, strict=True
        ):
            expected_count = expected_by_label[label]["total_messages"]
            invocation_count = 2 if continuation_count else 1
            scheduler_observed = row.get("queue_scheduler_observed")
            if not (
                isinstance(row, dict)
                and row.get("tier") == label
                and row.get("target") == "rust-candidate"
                and row.get("requested_messages") == expected_count
                and row.get("observer_verified_messages") == expected_count
                and (
                    (
                        continuation_candidate_stability
                        and row.get("endpoint_invocations") == invocation_count
                        and row.get("single_endpoint_invocation")
                        is (invocation_count == 1)
                        and row.get("same_process_continuation_required")
                        is (continuation_count > 0)
                        and row.get("same_process_continuation_messages")
                        == continuation_count
                        and row.get("same_process_continuation_passed") is True
                    )
                    or (
                        legacy_candidate_stability
                        and row.get("single_endpoint_invocation") is True
                    )
                )
                and isinstance(scheduler_observed, bool)
                and (not formal or scheduler_observed is True)
                and row.get("passed") is True
            ):
                raise SystemExit("candidate stability tier summaries changed")
        acceptance = value.get("acceptance")
        if not isinstance(acceptance, dict) or not (
            acceptance.get("passed") is True
            and acceptance.get("qualified") is qualified
            and acceptance.get("no_batching") is True
            and acceptance.get("candidate_stability") is True
            and acceptance.get("candidate_only") is True
            and acceptance.get("one_arm_per_tier") is True
            and acceptance.get("one_endpoint_invocation_per_tier")
            is (
                legacy_candidate_stability
                or not formal
                or not any(expected_continuations)
            )
            and (
                legacy_candidate_stability
                or (
                    acceptance.get(
                        "candidate_small_tiers_use_250k_plus_same_process_100k"
                    )
                    is (formal and any(expected_continuations))
                    and acceptance.get("same_process_continuation_gate_passed")
                    is True
                )
            )
            and acceptance.get("two_equally_weighted_arms_per_target_tier") is False
            and acceptance.get("both_paired_ratios_must_pass") is False
            and acceptance.get("conservative_min_rust_over_max_java_must_pass") is False
            and acceptance.get("cross_arm_stability_must_pass") is False
            and acceptance.get("no_warmup_endpoint_calls") is True
            and acceptance.get("no_repetition_loop") is True
            and acceptance.get("no_stress_start_retries") is True
        ):
            raise SystemExit("candidate stability acceptance semantics changed")
        methodology = value.get("methodology")
        if not isinstance(methodology, dict) or not (
            methodology.get("per_tier_arms") == ["rust-candidate"]
            and methodology.get("candidate_only_stability_tiers") == labels
            and methodology.get("one_large_start_invocation_per_arm")
            is (
                legacy_candidate_stability
                or not formal
                or not any(expected_continuations)
            )
            and (
                legacy_candidate_stability
                or (
                    methodology.get(
                        "candidate_stability_initial_small_tier_messages"
                    )
                    == (250_000 if formal and any(expected_continuations) else None)
                    and methodology.get(
                        "candidate_stability_same_process_continuation_messages"
                    )
                    == (100_000 if formal and any(expected_continuations) else None)
                    and methodology.get(
                        "candidate_stability_minimum_continuation_to_initial_ratio"
                    )
                    == (0.90 if formal and any(expected_continuations) else None)
                    and methodology.get("candidate_stability_continuation_tiers")
                    == [
                        label
                        for label, continuation in zip(
                            labels, expected_continuations, strict=True
                        )
                        if continuation
                    ]
                    and methodology.get("fresh_proxy_per_endpoint_invocation") is True
                    and methodology.get(
                        "same_candidate_process_for_initial_and_continuation"
                    )
                    is (formal and any(expected_continuations))
                )
            )
            and methodology.get("harness_batching") is False
            and methodology.get("automatic_endpoint_cleanup_only") is True
            and methodology.get("warmup_endpoint_invocations") == 0
            and methodology.get("repetition_loop") is False
            and methodology.get("performance_gate_uses_both_ordinal_pairs") is False
            and methodology.get("performance_gate_uses_min_rust_over_max_java") is False
            and methodology.get("performance_comparison_tiers") == []
            and methodology.get("cross_arm_relative_range_limit") is None
            and methodology.get("candidate_stability_is_qualification_evidence") is True
            and methodology.get("java_comparison_is_external") is True
        ):
            raise SystemExit("candidate stability methodology changed")
        rows = value.get("rows")
        if not isinstance(rows, list) or len(rows) != len(labels):
            raise SystemExit("candidate stability rows are missing")
        for plan, continuation_count, row in zip(
            plans, expected_continuations, rows, strict=True
        ):
            invocation_count = 2 if continuation_count else 1
            arms = row.get("arms") if isinstance(row, dict) else None
            measurements = row.get("measurements") if isinstance(row, dict) else None
            if not (
                row.get("target") == "rust-candidate"
                and row.get("tier") == plan
                and row.get("arm_count") == 1
                and row.get("endpoint_start_invocations") == invocation_count
                and row.get("endpoint_invocations") == invocation_count
                and row.get("harness_batches") == 0
                and row.get("requested_equals_observer_verified") is True
                and isinstance(arms, list)
                and len(arms) == 1
                and isinstance(measurements, list)
                and len(measurements) == 1
            ):
                raise SystemExit("candidate stability row shape changed")
            arm = arms[0]
            measurement = arm.get("measurement")
            continuation = arm.get("same_process_continuation")
            continuation_measurement = (
                continuation.get("measurement")
                if isinstance(continuation, dict)
                else None
            )
            continuation_gate = (
                continuation.get("gate") if isinstance(continuation, dict) else None
            )
            outcome = measurement.get("endpoint_outcome") if isinstance(measurement, dict) else None
            resource = measurement.get("resource") if isinstance(measurement, dict) else None
            count = plan["total_messages"]
            if not (
                arm.get("target") == "rust-candidate"
                and arm.get("arm_ordinal") == 0
                and arm.get("endpoint_start_invocations") == invocation_count
                and arm.get("endpoint_invocations") == invocation_count
                and arm.get("harness_batches") == 0
                and arm.get("endpoint_requested_messages") == count
                and arm.get("observer_verified_messages") == count
                and (
                    not continuation_candidate_stability
                    or (
                        arm.get("total_endpoint_requested_messages")
                        == count + continuation_count
                        and arm.get("total_observer_verified_messages")
                        == count + continuation_count
                    )
                )
                and arm.get("requested_equals_observer_verified") is True
                and valid_dkim_fixture(arm.get("dkim_fixture"))
                and isinstance(outcome, dict)
                and outcome.get("failure_count") == 0
                and outcome.get("retry_count") == 0
                and (not formal or outcome.get("queue_scheduler_observed") is True)
                and measurement.get("endpoint_start_invocation_count") == 1
                and measurement.get("endpoint_start_automatic_retries") == 0
                and measurement.get("smtp", {}).get(
                    "within_arm_throughput_stability", {}
                ).get("passed") is True
                and isinstance(resource, dict)
                and resource.get("candidate_cpu_usage_seconds", 0) > 0
                and resource.get("services_cpu_usage_seconds", 0) > 0
                and valid_application_persistence_io(arm, resource)
                and resource.get("services_persistence_io_observed") is True
                and resource.get("temperature", {}).get("within_limit") is True
            ):
                raise SystemExit("candidate stability single-call evidence changed")
            if continuation_candidate_stability and continuation_count:
                continuation_outcome = (
                    continuation_measurement.get("endpoint_outcome")
                    if isinstance(continuation_measurement, dict)
                    else None
                )
                continuation_resource = (
                    continuation_measurement.get("resource")
                    if isinstance(continuation_measurement, dict)
                    else None
                )
                if not (
                    isinstance(continuation, dict)
                    and isinstance(continuation_measurement, dict)
                    and isinstance(continuation_gate, dict)
                    and continuation_gate.get("required") is True
                    and continuation_gate.get("messages") == 100_000
                    and continuation_gate.get("fresh_proxy") is True
                    and continuation_gate.get("candidate_runtime_restarted") is False
                    and continuation_gate.get("candidate_runtime_identity_stable") is True
                    and continuation_gate.get("minimum_ratio") == 0.90
                    and continuation_gate.get(
                        "continuation_to_initial_prefix_ratio", 0
                    ) >= 0.90
                    and continuation_gate.get("passed") is True
                    and continuation_measurement.get(
                        "endpoint_start_invocation_count"
                    ) == 1
                    and continuation_measurement.get(
                        "endpoint_start_automatic_retries"
                    ) == 0
                    and continuation_measurement.get("smtp", {}).get("verified")
                    == 100_000
                    and continuation_measurement.get("smtp", {}).get(
                        "within_arm_throughput_stability", {}
                    ).get("passed") is True
                    and isinstance(continuation_outcome, dict)
                    and continuation_outcome.get("failure_count") == 0
                    and continuation_outcome.get("retry_count") == 0
                    and continuation_outcome.get("queue_scheduler_observed") is True
                    and isinstance(continuation_resource, dict)
                    and continuation_resource.get("candidate_cpu_usage_seconds", 0) > 0
                    and continuation_resource.get("services_cpu_usage_seconds", 0) > 0
                    and valid_application_persistence_io(
                        arm, continuation_resource
                    )
                    and continuation_resource.get(
                        "services_persistence_io_observed"
                    ) is True
                    and continuation_resource.get("temperature", {}).get(
                        "within_limit"
                    ) is True
                ):
                    raise SystemExit(
                        "candidate stability continuation evidence changed"
                    )
            elif continuation_candidate_stability and continuation is not None:
                raise SystemExit("candidate stability smoke/10MB gained a continuation")
        attestation = value.get("attestation")
        external = value.get("external_prerequisites")
        calibration = value.get("real_gate_calibration")
        if not (
            isinstance(attestation, dict)
            and isinstance(external, dict)
            and isinstance(calibration, dict)
        ):
            raise SystemExit("candidate stability provenance is missing")
        runner_sha = attestation.get("runner_sha256")
        launcher_sha = attestation.get("launcher_sha256")
        definition = attestation.get("benchmark_definition")
        definition_sha = definition.get("sha256") if isinstance(definition, dict) else None
        proxy_binary_sha = attestation.get("benchmark_proxy_release_sha256")
        proxy_source_sha = attestation.get("benchmark_proxy_source_tree_sha256")
        for digest in (
            runner_sha,
            launcher_sha,
            definition_sha,
            proxy_binary_sha,
            proxy_source_sha,
        ):
            if not valid_sha256(digest):
                raise SystemExit("candidate stability provenance digest is invalid")
        if formal:
            isolation = attestation.get("isolation_policy")
            proxy = external.get("proxy_headroom")
            if not (
                qualified is True
                and value.get("qualification_prerequisites_passed") is True
                and external.get("passed") is True
                and acceptance.get("external_prerequisites_passed") is True
                and acceptance.get("real_gate_calibration_passed") is True
                and calibration.get("required_for_qualification") is True
                and calibration.get("performed") is True
                and calibration.get("passed") is True
                and set(calibration.get("tiers", {})) == set(labels)
                and isinstance(isolation, dict)
                and isolation.get("passed") is True
                and external.get("launcher_sha256") == launcher_sha
                and isinstance(proxy, dict)
                and proxy.get("runner_sha256") == runner_sha
                and proxy.get("binary_sha256") == proxy_binary_sha
                and proxy.get("source_tree_sha256") == proxy_source_sha
                and comparison.get("proxy_headroom_passed") is True
            ):
                raise SystemExit("formal candidate stability evidence is not qualified")
        elif not (
            qualified is False
            and value.get("qualification_prerequisites_passed") is False
            and external.get("passed") is False
            and calibration.get("performed") is False
        ):
            raise SystemExit("candidate stability smoke provenance changed")
        return value, runner_run_id, profile, runner_sha, launcher_sha, definition_sha
    comparison = value.get("comparison")
    comparison_gates = [
        "all_passed",
        "pair_completeness_passed",
        "performance_passed",
        "operational_evidence_passed",
        "arm_completeness_passed",
        "measurement_evidence_passed",
        "within_arm_stability_passed",
        "zero_retry_gate_passed",
        "abba_stability_passed",
        "proxy_headroom_passed",
    ]
    if mixed_v2:
        comparison_gates.append("required_topology_passed")
    if not isinstance(comparison, dict) or not all(
        comparison.get(key) is True for key in comparison_gates
    ):
        raise SystemExit("provisional comparison gates did not all pass")
    performance_rows = comparison.get("comparisons")
    execution_order = value.get("execution_order")
    expected_tiers = (
        {entry.get("tier") for entry in execution_order}
        if isinstance(execution_order, list)
        and all(isinstance(entry, dict) for entry in execution_order)
        else set()
    )
    if (
        not isinstance(performance_rows, list)
        or not all(isinstance(entry, dict) for entry in performance_rows)
        or {entry.get("tier") for entry in performance_rows} != expected_tiers
        or len(performance_rows) != len(expected_tiers)
    ):
        raise SystemExit("provisional performance tier topology changed")
    for entry in performance_rows:
        if mixed_v2 and entry.get("tier") == "10MB":
            rust_arms = entry.get("rust_arm_messages_per_second")
            if not (
                entry.get("pair_complete") is False
                and entry.get("candidate_only_complete") is True
                and entry.get("java_present") is False
                and entry.get("rust_present") is True
                and entry.get("java_comparison_intentionally_excluded") is True
                and entry.get("passed") is True
                and isinstance(rust_arms, dict)
                and set(rust_arms) == {"0", "1"}
                and all(
                    isinstance(rate, (int, float))
                    and math.isfinite(rate)
                    and rate > 0
                    for rate in rust_arms.values()
                )
                and "java_arm_messages_per_second" not in entry
                and "paired_ratios" not in entry
                and "conservative_ratio_passed" not in entry
            ):
                raise SystemExit("provisional Rust-only 10MB gate changed")
            continue
        if not (
            entry.get("pair_complete") is True
            and entry.get("passed") is True
            and entry.get("conservative_ratio_passed") is True
            and isinstance(entry.get("paired_ratios"), list)
            and len(entry["paired_ratios"]) == 2
            and all(pair.get("passed") is True for pair in entry["paired_ratios"])
        ):
            raise SystemExit("provisional paired/conservative performance gate changed")
    if mixed_v2 and "10MB" in expected_tiers and sum(
        entry.get("tier") == "10MB" for entry in performance_rows
    ) != 1:
        raise SystemExit("provisional paired/conservative performance gates changed")
    acceptance = value.get("acceptance")
    if not isinstance(acceptance, dict) or not (
        acceptance.get("passed") is True
        and acceptance.get("qualified") is qualified
        and acceptance.get("no_batching") is True
        and acceptance.get("two_equally_weighted_arms_per_target_tier") is True
        and acceptance.get("no_warmup_endpoint_calls") is True
        and acceptance.get("no_repetition_loop") is True
        and acceptance.get("no_stress_start_retries") is True
        and acceptance.get("both_paired_ratios_must_pass") is True
        and acceptance.get("conservative_min_rust_over_max_java_must_pass") is True
        and acceptance.get("cross_arm_stability_must_pass") is True
    ):
        raise SystemExit("provisional acceptance semantics changed")
    if legacy_abba:
        if acceptance.get("per_tier_abba") is not True:
            raise SystemExit("legacy ABBA acceptance semantics changed")
    elif not (
        acceptance.get("ten_megabyte_java_prohibited") is True
        and acceptance.get("ten_megabyte_rust_only") is ("10MB" in expected_tiers)
        and acceptance.get("per_tier_abba") is ("10MB" not in expected_tiers)
        and acceptance.get("small_message_tiers_abba")
        is bool(expected_tiers & {"1KB", "10KB"})
    ):
        raise SystemExit("mixed-v2 acceptance topology changed")
    methodology = value.get("methodology")
    if not isinstance(methodology, dict) or not (
        methodology.get("one_large_start_invocation_per_arm") is True
        and methodology.get("harness_batching") is False
        and methodology.get("automatic_endpoint_cleanup_only") is True
        and methodology.get("cleanup_excluded_from_throughput") is True
        and methodology.get("warmup_endpoint_invocations") == 0
        and methodology.get("repetition_loop") is False
        and methodology.get("stress_start_maximum_attempts_per_arm") == 1
        and methodology.get("stress_start_automatic_retries") == 0
        and methodology.get("uncertain_start_outcome")
        == "fail_closed_and_restart_as_a_new_benchmark_run"
        and methodology.get("fresh_runtime_database_redis_workspace_and_proxy_per_arm") is True
        and methodology.get("proxy_headroom_computed_against_maximum_observed_arm") is True
        and methodology.get("performance_gate_uses_both_ordinal_pairs") is True
        and methodology.get("performance_gate_uses_min_rust_over_max_java") is True
    ):
        raise SystemExit("provisional methodology semantics changed")
    if mixed_v2 and not (
        methodology.get("performance_comparison_tiers") == ["1KB", "10KB"]
        and methodology.get("candidate_only_stability_tiers") == ["10MB"]
    ):
        raise SystemExit("mixed-v2 methodology topology changed")
    rows = value.get("rows")
    if not isinstance(rows, list) or not rows:
        raise SystemExit("provisional ABBA rows are missing")
    for row in rows:
        arms = row.get("arms") if isinstance(row, dict) else None
        measurements = row.get("measurements") if isinstance(row, dict) else None
        if not (
            isinstance(arms, list)
            and len(arms) == 2
            and isinstance(measurements, list)
            and len(measurements) == 2
            and row.get("arm_count") == 2
            and row.get("endpoint_start_invocations") == 2
            and row.get("endpoint_invocations") == 2
            and row.get("harness_batches") == 0
            and row.get("requested_equals_observer_verified") is True
            and row.get("warmups") == []
            and all(
                arm.get("endpoint_start_invocations") == 1
                and arm.get("endpoint_invocations") == 1
                and arm.get("harness_batches") == 0
                and arm.get("endpoint_requested_messages")
                == arm.get("observer_verified_messages")
                and arm.get("requested_equals_observer_verified") is True
                and isinstance(arm.get("measurement"), dict)
                and arm["measurement"].get("endpoint_start_invocation_count") == 1
                and arm["measurement"].get("endpoint_start_automatic_retries") == 0
                and arm["measurement"].get("uncertain_start_outcome_policy")
                == "fail_closed_and_restart_as_a_new_benchmark_run"
                and isinstance(arm["measurement"].get("smtp"), dict)
                and arm["measurement"]["smtp"].get(
                    "within_arm_throughput_stability", {}
                ).get("passed") is True
                and isinstance(arm["measurement"].get("resource"), dict)
                and arm["measurement"]["resource"].get("candidate_cpu_usage_seconds", 0) > 0
                and arm["measurement"]["resource"].get("services_cpu_usage_seconds", 0) > 0
                and valid_application_persistence_io(
                    arm, arm["measurement"]["resource"]
                )
                and arm["measurement"]["resource"].get("services_persistence_io_observed") is True
                and isinstance(arm["measurement"]["resource"].get("temperature"), dict)
                and arm["measurement"]["resource"]["temperature"].get("within_limit") is True
                for arm in arms
            )
        ):
            raise SystemExit("provisional row did not preserve two single-call ABBA arms")
    attestation = value.get("attestation")
    external = value.get("external_prerequisites")
    if not isinstance(attestation, dict) or not isinstance(external, dict):
        raise SystemExit("provisional provenance is missing")
    runner_sha = attestation.get("runner_sha256")
    launcher_sha = attestation.get("launcher_sha256")
    definition = attestation.get("benchmark_definition")
    definition_sha = definition.get("sha256") if isinstance(definition, dict) else None
    proxy_binary_sha = attestation.get("benchmark_proxy_release_sha256")
    proxy_source_sha = attestation.get("benchmark_proxy_source_tree_sha256")
    for digest in (
        runner_sha,
        launcher_sha,
        definition_sha,
        proxy_binary_sha,
        proxy_source_sha,
    ):
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise SystemExit("provisional provenance digest is invalid")
    if formal:
        isolation = attestation.get("isolation_policy")
        proxy = external.get("proxy_headroom")
        paired_tiers = ("1KB", "10KB", "10MB") if legacy_abba else ("1KB", "10KB")
        expected_order = [
            {"target": target, "tier": tier, "arm_ordinal": ordinal}
            for tier in paired_tiers
            for target, ordinal in (
                ("java-oracle", 0),
                ("rust-candidate", 0),
                ("rust-candidate", 1),
                ("java-oracle", 1),
            )
        ]
        if mixed_v2:
            expected_order.extend(
                {"target": "rust-candidate", "tier": "10MB", "arm_ordinal": ordinal}
                for ordinal in (0, 1)
            )
        formal_topology_passed = (
            acceptance.get("per_tier_abba") is True
            if legacy_abba
            else (
                acceptance.get("per_tier_abba") is False
                and acceptance.get("small_message_tiers_abba") is True
                and acceptance.get("ten_megabyte_java_prohibited") is True
                and acceptance.get("ten_megabyte_rust_only") is True
            )
        )
        if not (
            qualified is True
            and value.get("qualification_prerequisites_passed") is True
            and external.get("passed") is True
            and acceptance.get("external_prerequisites_passed") is True
            and isinstance(isolation, dict)
            and isolation.get("passed") is True
            and external.get("launcher_sha256") == launcher_sha
            and isinstance(proxy, dict)
            and proxy.get("runner_sha256") == runner_sha
            and proxy.get("binary_sha256") == proxy_binary_sha
            and proxy.get("source_tree_sha256") == proxy_source_sha
            and comparison.get("proxy_headroom_passed") is True
            and formal_topology_passed
            and value.get("execution_order") == expected_order
        ):
            raise SystemExit("formal provisional evidence is not qualified")
    return value, runner_run_id, profile, runner_sha, launcher_sha, definition_sha


def validate_checkpoint(payload, output_value, output_sha, runner_run_id, qualified):
    records = []
    previous = None
    for sequence, line in enumerate(payload.splitlines()):
        if not line:
            raise SystemExit("completed checkpoint contains an empty record")
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SystemExit("completed checkpoint is not valid JSONL") from error
        if not isinstance(record, dict):
            raise SystemExit("completed checkpoint record is not an object")
        digest = record.get("_record_sha256")
        unsigned = {key: value for key, value in record.items() if key != "_record_sha256"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        if not (
            record.get("_sequence") == sequence
            and record.get("_previous_record_sha256") == previous
            and isinstance(digest, str)
            and hashlib.sha256(canonical).hexdigest() == digest
        ):
            raise SystemExit("completed checkpoint hash chain is invalid")
        previous = digest
        records.append(record)
    if len(records) < 2:
        raise SystemExit("completed checkpoint is incomplete")
    started = records[0]
    completed = records[-1]
    if not (
        started.get("event") == "started"
        and started.get("run_id") == runner_run_id
        and started.get("launcher_run_id") == launcher_run_id
        and started.get("benchmark_profile") == output_value.get("profile")
        and started.get("rust_filesystem_fsync")
        == output_value.get("rust_filesystem_fsync")
        and completed.get("event") == "completed"
        and completed.get("run_id") == runner_run_id
        and completed.get("launcher_run_id") == launcher_run_id
        and completed.get("status") == "passed"
        and completed.get("qualified") is qualified
        and completed.get("rust_filesystem_fsync")
        == output_value.get("rust_filesystem_fsync")
        and completed.get("output") == logical_relative
        and completed.get("output_sha256") == output_sha
        and completed.get("comparison") == output_value.get("comparison")
    ):
        raise SystemExit("completed checkpoint provenance differs from the output")


output_path, output_descriptor, output_metadata, output_identity = open_artifact(
    output_raw,
    "provisional output",
    0o444,
    expected_output_device,
    expected_output_inode,
    expected_output_size,
)
checkpoint_path, checkpoint_descriptor, checkpoint_metadata, checkpoint_identity = open_artifact(
    checkpoint_raw,
    "completed checkpoint",
    0o400,
    expected_checkpoint_device,
    expected_checkpoint_inode,
    expected_checkpoint_size,
)
try:
    output_payload = read_bounded(output_descriptor, 64 * 1024 * 1024, "provisional output")
    checkpoint_payload = read_bounded(
        checkpoint_descriptor, 64 * 1024 * 1024, "completed checkpoint"
    )
    output_sha = hashlib.sha256(output_payload).hexdigest()
    checkpoint_sha = hashlib.sha256(checkpoint_payload).hexdigest()
    (
        output_value,
        runner_run_id,
        profile,
        runner_sha,
        launcher_sha,
        definition_sha,
    ) = validate_output(output_payload)
    validate_checkpoint(
        checkpoint_payload,
        output_value,
        output_sha,
        runner_run_id,
        output_value["qualified"],
    )
    if mode == "promote":
        os.fchown(output_descriptor, 0, 0)
        os.fchmod(output_descriptor, 0o444)
        os.fsync(output_descriptor)
        os.fchown(checkpoint_descriptor, 0, 0)
        os.fchmod(checkpoint_descriptor, 0o400)
        os.fsync(checkpoint_descriptor)
        for path in {output_path.parent, checkpoint_path.parent}:
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    allowed_links = (1,) if mode == "promote" else (1, 2)
    for descriptor, path, identity, expected_mode, payload, digest, label in (
        (
            output_descriptor,
            output_path,
            output_identity,
            0o444,
            output_payload,
            output_sha,
            "provisional output",
        ),
        (
            checkpoint_descriptor,
            checkpoint_path,
            checkpoint_identity,
            0o400,
            checkpoint_payload,
            checkpoint_sha,
            "completed checkpoint",
        ),
    ):
        current = os.fstat(descriptor)
        path_current = path.lstat()
        if not (
            (current.st_dev, current.st_ino) == identity
            and (path_current.st_dev, path_current.st_ino) == identity
            and current.st_uid == path_current.st_uid == 0
            and current.st_gid == path_current.st_gid == 0
            and stat.S_IMODE(current.st_mode) == stat.S_IMODE(path_current.st_mode) == expected_mode
            and current.st_nlink == path_current.st_nlink
            and current.st_nlink in allowed_links
            and current.st_size == path_current.st_size == len(payload)
        ):
            raise SystemExit(f"{label} changed during root promotion")
        if hashlib.sha256(read_bounded(descriptor, 64 * 1024 * 1024, label)).hexdigest() != digest:
            raise SystemExit(f"{label} content changed during root promotion")
    if mode == "validate" and (
        output_sha != expected_output_sha or checkpoint_sha != expected_checkpoint_sha
    ):
        raise SystemExit("root-owned artifact hash differs from the runner receipt")
finally:
    os.close(checkpoint_descriptor)
    os.close(output_descriptor)

print(f"runner_run_id={runner_run_id}")
print(f"benchmark_profile={profile}")
print(f"rust_filesystem_fsync={expected_rust_fsync}")
print(f"runner_sha256={runner_sha}")
print(f"launcher_sha256={launcher_sha}")
print(f"definition_sha256={definition_sha}")
print(f"output_sha256={output_sha}")
print(f"output_device={output_identity[0]}")
print(f"output_inode={output_identity[1]}")
print(f"output_size={len(output_payload)}")
print(f"checkpoint_sha256={checkpoint_sha}")
print(f"checkpoint_device={checkpoint_identity[0]}")
print(f"checkpoint_inode={checkpoint_identity[1]}")
print(f"checkpoint_size={len(checkpoint_payload)}")
PY
}

write_runner_success() {
    local path=$1 checkpoint=$2 logical_output=$3 pid=$4 start_time=$5 fields
    local payload
    local runner_run_id profile runner_fsync runner_sha launcher_sha definition_sha
    local output_sha output_device output_inode output_size
    local checkpoint_sha checkpoint_device checkpoint_inode checkpoint_size
    [[ ${pid} =~ ^[1-9][0-9]*$ && ${start_time} =~ ^[1-9][0-9]*$ ]] || return 1
    fields=$(inspect_runner_artifacts \
        promote "${path}" "${checkpoint}" "${logical_output}" \
        "${run_id}" "${formal_run}" "${rust_filesystem_fsync}") \
        || return 1
    runner_run_id=$(read_payload_value "${fields}" runner_run_id) || return 1
    profile=$(read_payload_value "${fields}" benchmark_profile) || return 1
    runner_fsync=$(read_payload_value "${fields}" rust_filesystem_fsync) || return 1
    [[ ${runner_fsync} == "${rust_filesystem_fsync}" ]] || return 1
    runner_sha=$(read_payload_value "${fields}" runner_sha256) || return 1
    launcher_sha=$(read_payload_value "${fields}" launcher_sha256) || return 1
    definition_sha=$(read_payload_value "${fields}" definition_sha256) || return 1
    output_sha=$(read_payload_value "${fields}" output_sha256) || return 1
    output_device=$(read_payload_value "${fields}" output_device) || return 1
    output_inode=$(read_payload_value "${fields}" output_inode) || return 1
    output_size=$(read_payload_value "${fields}" output_size) || return 1
    checkpoint_sha=$(read_payload_value "${fields}" checkpoint_sha256) || return 1
    checkpoint_device=$(read_payload_value "${fields}" checkpoint_device) || return 1
    checkpoint_inode=$(read_payload_value "${fields}" checkpoint_inode) || return 1
    checkpoint_size=$(read_payload_value "${fields}" checkpoint_size) || return 1
    payload=$(printf '%s\n' \
        'schema_version=2' \
        "run_id=${run_id}" \
        "runner_run_id=${runner_run_id}" \
        "benchmark_profile=${profile}" \
        "rust_filesystem_fsync=${runner_fsync}" \
        "runner_pid=${pid}" \
        "runner_start_time=${start_time}" \
        "formal_run=${formal_run}" \
        "provisional_path=${logical_output}" \
        "checkpoint_path=${logical_output}.complete.jsonl" \
        "output_artifact=${path}" \
        "checkpoint_artifact=${checkpoint}" \
        "provisional_sha256=${output_sha}" \
        "provisional_device=${output_device}" \
        "provisional_inode=${output_inode}" \
        "provisional_size=${output_size}" \
        "output_sha256=${output_sha}" \
        "output_device=${output_device}" \
        "output_inode=${output_inode}" \
        "output_size=${output_size}" \
        "checkpoint_sha256=${checkpoint_sha}" \
        "checkpoint_device=${checkpoint_device}" \
        "checkpoint_inode=${checkpoint_inode}" \
        "checkpoint_size=${checkpoint_size}" \
        "runner_sha256=${runner_sha}" \
        "launcher_sha256=${launcher_sha}" \
        "definition_sha256=${definition_sha}") || return 1
    write_journal_once "${runner_success_path}" "${payload}"
}

write_intent() {
    local payload
    payload=$(printf '%s\n' \
        'schema_version=3' \
        "run_id=${run_id}" \
        "benchmark_group=${benchmark_group}" \
        "image_path=${image_path}" \
        "output_artifact=${output_artifact}" \
        "checkpoint_artifact=${checkpoint_artifact}" \
        "quota_mount=${quota_mount}" \
        "image_bytes=${image_bytes}" \
        "formal_run=${formal_run}" \
        "rust_filesystem_fsync=${rust_filesystem_fsync}" \
        "final_output=${final_output}" \
        "provisional_output=${provisional_output}") || return 1
    write_journal_once "${intent_path}" "${payload}"
}

validate_intent() {
    local path=$1 identifier=$2 expected schema
    schema=$(read_journal_value "${path}" schema_version) || return 1
    [[ ${schema} == 1 || ${schema} == 2 || ${schema} == 3 ]] || return 1
    [[ $(read_journal_value "${path}" run_id) == "${identifier}" ]] || return 1
    derive_run_paths "${identifier}" || return 1
    for key in benchmark_group image_path quota_mount; do
        expected=${!key}
        [[ $(read_journal_value "${path}" "${key}") == "${expected}" ]] || return 1
    done
    if (( schema >= 2 )); then
        for key in output_artifact checkpoint_artifact; do
            expected=${!key}
            [[ $(read_journal_value "${path}" "${key}") == "${expected}" ]] || return 1
        done
    fi
    if (( schema >= 3 )); then
        expected=$(read_journal_value "${path}" rust_filesystem_fsync) || return 1
        [[ ${expected} == on || ${expected} == off \
            || ${expected} == not-applicable ]] || return 1
    fi
}

validate_runner_success() {
    local identifier=$1 expected_pid=${2:-} expected_start_time=${3:-}
    local metadata journal_pid journal_start provisional checkpoint artifact_output
    local artifact_checkpoint final actual_output artifact_identity checkpoint_identity
    local actual_checkpoint formal intent_fsync fields key expected actual
    local output_sha output_device output_inode output_size
    local checkpoint_sha checkpoint_device checkpoint_inode checkpoint_size
    derive_run_paths "${identifier}" || return 1
    [[ -f ${intent_path} && ! -L ${intent_path} \
        && -f ${runner_success_path} && ! -L ${runner_success_path} ]] || return 1
    metadata=$(stat -c '%u:%g:%a:%h:%F' -- "${runner_success_path}") || return 1
    [[ ${metadata} == '0:0:400:1:regular file' ]] || return 1
    [[ $(read_journal_value "${runner_success_path}" schema_version) == 2 ]] || return 1
    [[ $(read_journal_value "${runner_success_path}" run_id) == "${identifier}" ]] \
        || return 1
    journal_pid=$(read_journal_value "${runner_success_path}" runner_pid) || return 1
    journal_start=$(read_journal_value "${runner_success_path}" runner_start_time) || return 1
    [[ ${journal_pid} =~ ^[1-9][0-9]*$ && ${journal_start} =~ ^[1-9][0-9]*$ ]] \
        || return 1
    [[ -z ${expected_pid} || ${journal_pid} == "${expected_pid}" ]] || return 1
    [[ -z ${expected_start_time} || ${journal_start} == "${expected_start_time}" ]] \
        || return 1
    provisional=$(read_journal_value "${runner_success_path}" provisional_path) || return 1
    [[ ${provisional} == "$(read_journal_value "${intent_path}" provisional_output)" ]] \
        || return 1
    checkpoint=$(read_journal_value "${runner_success_path}" checkpoint_path) || return 1
    [[ ${checkpoint} == "${provisional}.complete.jsonl" ]] || return 1
    artifact_output=$(read_journal_value \
        "${runner_success_path}" output_artifact) || return 1
    artifact_checkpoint=$(read_journal_value \
        "${runner_success_path}" checkpoint_artifact) || return 1
    [[ ${artifact_output} == "$(read_journal_value "${intent_path}" output_artifact)" \
        && ${artifact_checkpoint} \
        == "$(read_journal_value "${intent_path}" checkpoint_artifact)" ]] || return 1
    formal=$(read_journal_value "${intent_path}" formal_run) || return 1
    [[ ${formal} == 0 || ${formal} == 1 ]] || return 1
    [[ $(read_journal_value "${runner_success_path}" formal_run) == "${formal}" ]] \
        || return 1
    intent_fsync=$(read_journal_value "${intent_path}" rust_filesystem_fsync) || return 1
    [[ ${intent_fsync} == on || ${intent_fsync} == off \
        || ${intent_fsync} == not-applicable ]] || return 1
    [[ $(read_journal_value "${runner_success_path}" rust_filesystem_fsync) \
        == "${intent_fsync}" ]] || return 1
    final=$(read_journal_value "${intent_path}" final_output) || return 1
    output_sha=$(read_journal_value "${runner_success_path}" provisional_sha256) || return 1
    output_device=$(read_journal_value "${runner_success_path}" provisional_device) || return 1
    output_inode=$(read_journal_value "${runner_success_path}" provisional_inode) || return 1
    output_size=$(read_journal_value "${runner_success_path}" provisional_size) || return 1
    checkpoint_sha=$(read_journal_value "${runner_success_path}" checkpoint_sha256) || return 1
    checkpoint_device=$(read_journal_value "${runner_success_path}" checkpoint_device) || return 1
    checkpoint_inode=$(read_journal_value "${runner_success_path}" checkpoint_inode) || return 1
    checkpoint_size=$(read_journal_value "${runner_success_path}" checkpoint_size) || return 1
    [[ ${output_sha} =~ ^[0-9a-f]{64}$ && ${checkpoint_sha} =~ ^[0-9a-f]{64}$ \
        && ${output_device} =~ ^[0-9]+$ && ${output_inode} =~ ^[1-9][0-9]*$ \
        && ${output_size} =~ ^[1-9][0-9]*$ && ${checkpoint_device} =~ ^[0-9]+$ \
        && ${checkpoint_inode} =~ ^[1-9][0-9]*$ \
        && ${checkpoint_size} =~ ^[1-9][0-9]*$ ]] || return 1
    artifact_identity=$(stat -c '%d:%i' -- "${artifact_output}" 2>/dev/null || true)
    if [[ -f ${artifact_output} && ! -L ${artifact_output} \
        && ${artifact_identity} == "${output_device}:${output_inode}" ]]; then
        actual_output=${artifact_output}
    elif [[ -f ${final} && ! -L ${final} ]]; then
        actual_output=${final}
    else
        return 1
    fi
    checkpoint_identity=$(stat -c '%d:%i' -- "${artifact_checkpoint}" 2>/dev/null || true)
    if [[ -f ${artifact_checkpoint} && ! -L ${artifact_checkpoint} \
        && ${checkpoint_identity} == "${checkpoint_device}:${checkpoint_inode}" ]]; then
        actual_checkpoint=${artifact_checkpoint}
    elif [[ -f ${final}.runner.complete.jsonl \
        && ! -L ${final}.runner.complete.jsonl ]]; then
        actual_checkpoint=${final}.runner.complete.jsonl
    else
        return 1
    fi
    fields=$(inspect_runner_artifacts validate \
        "${actual_output}" "${actual_checkpoint}" "${provisional}" \
        "${identifier}" "${formal}" "${intent_fsync}" \
        "${output_sha}" "${output_device}" "${output_inode}" "${output_size}" \
        "${checkpoint_sha}" "${checkpoint_device}" "${checkpoint_inode}" \
        "${checkpoint_size}") || return 1
    for key in runner_run_id benchmark_profile rust_filesystem_fsync \
        runner_sha256 launcher_sha256 \
        definition_sha256 output_sha256 output_device output_inode output_size \
        checkpoint_sha256 checkpoint_device checkpoint_inode checkpoint_size; do
        expected=$(read_journal_value "${runner_success_path}" "${key}") || return 1
        actual=$(read_payload_value "${fields}" "${key}") || return 1
        [[ ${actual} == "${expected}" ]] || return 1
    done
}

publish_hardlink_once() {
    local source=$1 destination=$2 remove_source=$3
    local expected_device=${4:-} expected_inode=${5:-} expected_mode=${6:-400}
    local expected_sha=${7:-}
    local partial_record=${8:-} operation=${9:-}
    local journal_source=${10:-${source}} journal_destination=${11:-${destination}}
    "${venv_python}" - "${source}" "${destination}" "${remove_source}" \
        "${expected_device}" "${expected_inode}" "${expected_mode}" \
        "${expected_sha}" "${partial_record}" "${operation}" \
        "${journal_source}" "${journal_destination}" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
remove_source = sys.argv[3] == "1"
(
    expected_device_raw,
    expected_inode_raw,
    expected_mode_raw,
    expected_sha,
    partial_record_raw,
    operation,
    journal_source_raw,
    journal_destination_raw,
) = sys.argv[4:]
if sys.argv[3] not in {"0", "1"}:
    raise SystemExit("hardlink source removal flag is invalid")
if bool(expected_device_raw) != bool(expected_inode_raw):
    raise SystemExit("hardlink expected identity is incomplete")
expected_identity = (
    (int(expected_device_raw), int(expected_inode_raw))
    if expected_device_raw
    else None
)
expected_mode = int(expected_mode_raw, 8)
partial_record = pathlib.Path(partial_record_raw) if partial_record_raw else None
journal_source = pathlib.Path(journal_source_raw)
journal_destination = pathlib.Path(journal_destination_raw)
if expected_sha and (
    len(expected_sha) != 64
    or any(character not in "0123456789abcdef" for character in expected_sha)
):
    raise SystemExit("hardlink expected SHA-256 is invalid")
if partial_record is not None:
    if operation not in {"output", "checkpoint"}:
        raise SystemExit("partial publish operation is invalid")
    if expected_identity is None or not expected_sha:
        raise SystemExit("partial publish identity and hash are required")
    if not all(
        path.is_absolute()
        for path in (source, destination, partial_record, journal_source, journal_destination)
    ):
        raise SystemExit("partial publish paths must be absolute")
    if destination != journal_destination or source not in {
        journal_source,
        journal_destination,
    }:
        raise SystemExit("partial publish recovery paths changed")
elif remove_source:
    raise SystemExit("source-removing publication requires a partial journal")
descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
destination_directory = os.open(
    destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
)
created_destination = False
removed_source = False
identity = None


def fsync_directory(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def path_identity(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    return metadata.st_dev, metadata.st_ino


def partial_value(stage):
    return {
        "schema_version": 1,
        "operation": operation,
        "source": str(journal_source),
        "destination": str(journal_destination),
        "device": identity[0],
        "inode": identity[1],
        "expected_mode": format(expected_mode, "03o"),
        "expected_sha256": expected_sha,
        "stage": stage,
    }


def validate_partial_payload(payload):
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OSError("partial publish journal is invalid") from error
    allowed_stages = {
        "source-identity-conflict",
        "source-restore-failed",
        "source-restore-durability-unverified",
    }
    if set(value) != set(partial_value("source-restore-failed")):
        raise OSError("partial publish journal fields changed")
    if value.get("stage") not in allowed_stages:
        raise OSError("partial publish journal stage is invalid")
    expected = partial_value(value["stage"])
    if value != expected:
        raise OSError("partial publish journal identity changed")


def read_descriptor_bytes(file_descriptor):
    os.lseek(file_descriptor, 0, os.SEEK_SET)
    payload = bytearray()
    while True:
        chunk = os.read(file_descriptor, 64 * 1024)
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


def validate_partial_record(file_descriptor, allowed_link_counts={1}):
    metadata = os.fstat(file_descriptor)
    if not (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o400
        and metadata.st_nlink in allowed_link_counts
        and 0 < metadata.st_size <= 4096
    ):
        raise OSError("partial publish journal metadata is invalid")
    validate_partial_payload(read_descriptor_bytes(file_descriptor))
    return metadata


def partial_temporary_path():
    return partial_record.with_name(f".{partial_record.name}.tmp")


def durable_record_partial_publish(stage):
    if partial_record is None:
        return
    payload = (
        json.dumps(partial_value(stage), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    temporary = partial_temporary_path()
    try:
        existing = os.open(partial_record, flags)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        try:
            metadata = validate_partial_record(existing, {1, 2})
            temporary_identity = path_identity(temporary)
            if metadata.st_nlink == 2:
                if temporary_identity != (metadata.st_dev, metadata.st_ino):
                    raise OSError("partial publish journal alias is missing")
                temporary_descriptor = os.open(temporary, flags)
                try:
                    validate_partial_record(temporary_descriptor, {2})
                finally:
                    os.close(temporary_descriptor)
                temporary.unlink()
                fsync_directory(partial_record.parent)
                validate_partial_record(existing)
            elif temporary_identity is not None:
                raise OSError("partial publish journal has an unexpected temporary")
            os.fsync(existing)
        finally:
            os.close(existing)
        fsync_directory(partial_record.parent)
        return
    try:
        temporary_descriptor = os.open(temporary, flags)
    except FileNotFoundError:
        temporary_descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o400,
        )
        try:
            with os.fdopen(temporary_descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    else:
        try:
            validate_partial_record(temporary_descriptor)
        finally:
            os.close(temporary_descriptor)
    try:
        os.link(temporary, partial_record, follow_symlinks=False)
        fsync_directory(partial_record.parent)
        temporary.unlink()
        fsync_directory(partial_record.parent)
        marker_descriptor = os.open(partial_record, flags)
        try:
            validate_partial_record(marker_descriptor)
        finally:
            os.close(marker_descriptor)
    finally:
        try:
            temporary.unlink(missing_ok=True)
            fsync_directory(partial_record.parent)
        except OSError:
            pass


def clear_partial_publish():
    if partial_record is None:
        return
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    temporary = partial_temporary_path()
    try:
        marker_descriptor = os.open(partial_record, flags)
    except FileNotFoundError:
        temporary.unlink(missing_ok=True)
        fsync_directory(partial_record.parent)
        return
    try:
        metadata = validate_partial_record(marker_descriptor, {1, 2})
        temporary_identity = path_identity(temporary)
        if metadata.st_nlink == 2:
            if temporary_identity != (metadata.st_dev, metadata.st_ino):
                raise OSError("partial publish journal alias is missing")
            temporary.unlink()
            fsync_directory(partial_record.parent)
            validate_partial_record(marker_descriptor)
        elif temporary_identity is not None:
            raise OSError("partial publish journal has an unexpected temporary")
    finally:
        os.close(marker_descriptor)
    partial_record.unlink()
    fsync_directory(partial_record.parent)


def rollback():
    if identity is None:
        return
    source_restored = False
    stage = "source-identity-conflict"
    try:
        source_state = path_identity(source)
    except OSError:
        source_state = None
        stage = "source-restore-failed"
    if not removed_source:
        source_restored = source_state == identity
    elif source_state is None:
        try:
            os.link(f"/proc/self/fd/{descriptor}", source, follow_symlinks=True)
        except OSError:
            stage = "source-restore-failed"
        else:
            try:
                fsync_directory(source.parent)
            except OSError:
                stage = "source-restore-durability-unverified"
            else:
                try:
                    source_restored = path_identity(source) == identity
                except OSError:
                    source_restored = False
                if not source_restored:
                    stage = "source-identity-conflict"
    elif source_state == identity:
        try:
            fsync_directory(source.parent)
            source_restored = path_identity(source) == identity
            if not source_restored:
                stage = "source-identity-conflict"
        except OSError:
            stage = "source-restore-durability-unverified"
    try:
        destination_matches = path_identity(destination) == identity
    except OSError:
        destination_matches = False
    if source_restored:
        if created_destination and destination_matches:
            try:
                os.unlink(destination.name, dir_fd=destination_directory)
                os.fsync(destination_directory)
            except OSError:
                pass
        return
    if remove_source and destination_matches:
        try:
            durable_record_partial_publish(stage)
        except OSError:
            # The destination remains the recovery capability even if the
            # diagnostic journal itself cannot be made durable.
            pass


try:
    before = os.fstat(descriptor)
    source_before = source.lstat()
    identity = (before.st_dev, before.st_ino)
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit("hardlink source has invalid metadata")
    if (source_before.st_dev, source_before.st_ino) != identity:
        raise SystemExit("hardlink source path changed after open")
    if before.st_uid != 0 or before.st_gid != 0 or stat.S_IMODE(before.st_mode) != expected_mode:
        raise SystemExit("hardlink source is not immutable root-owned evidence")
    if expected_identity is not None and identity != expected_identity:
        raise SystemExit("hardlink source identity differs from the runner receipt")
    if expected_sha:
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            payload.extend(chunk)
        if hashlib.sha256(payload).hexdigest() != expected_sha:
            raise SystemExit("hardlink source hash differs from the runner receipt")
        os.lseek(descriptor, 0, os.SEEK_SET)
    if source == destination:
        destination_before = os.stat(
            destination.name, dir_fd=destination_directory, follow_symlinks=False
        )
        if not (
            (destination_before.st_dev, destination_before.st_ino) == identity
            and before.st_nlink == destination_before.st_nlink == 1
        ):
            raise SystemExit("recovered hardlink identity changed")
        clear_partial_publish()
    else:
        try:
            destination_before = os.stat(
                destination.name, dir_fd=destination_directory, follow_symlinks=False
            )
        except FileNotFoundError:
            destination_before = None
        if destination_before is None:
            if before.st_nlink != 1:
                raise SystemExit("new hardlink source is not singly linked")
            os.link(
                f"/proc/self/fd/{descriptor}",
                destination.name,
                dst_dir_fd=destination_directory,
                follow_symlinks=True,
            )
            created_destination = True
        elif (destination_before.st_dev, destination_before.st_ino) != identity:
            raise FileExistsError(f"create-only hardlink destination differs: {destination}")
        elif before.st_nlink != 2:
            raise SystemExit("existing hardlink pair has an invalid link count")
        linked = os.fstat(descriptor)
        source_linked = source.lstat()
        destination_linked = os.stat(
            destination.name, dir_fd=destination_directory, follow_symlinks=False
        )
        if not (
            (linked.st_dev, linked.st_ino) == identity
            and (source_linked.st_dev, source_linked.st_ino) == identity
            and (destination_linked.st_dev, destination_linked.st_ino) == identity
            and linked.st_nlink == 2
            and source_linked.st_nlink == linked.st_nlink
            and destination_linked.st_nlink == linked.st_nlink
        ):
            raise SystemExit("published hardlink identity changed")
        os.fsync(destination_directory)
        if remove_source:
            source_current = source.lstat()
            if (source_current.st_dev, source_current.st_ino) != identity:
                raise SystemExit("hardlink source path changed before unlink")
            source.unlink()
            removed_source = True
            fsync_directory(source.parent)
            final = os.fstat(descriptor)
            destination_final = os.stat(
                destination.name, dir_fd=destination_directory, follow_symlinks=False
            )
            if not (
                (final.st_dev, final.st_ino) == identity
                and (destination_final.st_dev, destination_final.st_ino) == identity
                and final.st_nlink == destination_final.st_nlink == 1
            ):
                raise SystemExit("published hardlink changed after source unlink")
        clear_partial_publish()
except BaseException:
    rollback()
    raise
finally:
    os.close(destination_directory)
    os.close(descriptor)
PY
}

publish_provisional() {
    local identifier=$1 intent final provisional receipt_target checkpoint_source
    local evidence_source output_sha output_device output_inode
    local checkpoint_sha checkpoint_device checkpoint_inode
    local artifact_identity checkpoint_identity
    derive_run_paths "${identifier}" || return 1
    intent=${intent_path}
    final=$(read_journal_value "${intent}" final_output) || return 1
    provisional=$(read_journal_value "${intent}" provisional_output) || return 1
    [[ $(read_journal_value "${done_path}" qualified_cleanup) == 1 ]] || return 1
    [[ $(read_journal_value "${done_path}" lazy_unmount) == 0 ]] || return 1
    [[ -f ${runner_success_path} && ! -L ${runner_success_path} ]] || return 1
    [[ $(read_journal_value "${runner_success_path}" schema_version) == 2 ]] || return 1
    [[ $(read_journal_value "${runner_success_path}" provisional_path) == "${provisional}" ]] \
        || return 1
    [[ $(read_journal_value "${runner_success_path}" output_artifact) \
        == "${output_artifact}" \
        && $(read_journal_value "${runner_success_path}" checkpoint_artifact) \
        == "${checkpoint_artifact}" ]] || return 1
    output_sha=$(read_journal_value "${runner_success_path}" output_sha256) || return 1
    output_device=$(read_journal_value "${runner_success_path}" output_device) || return 1
    output_inode=$(read_journal_value "${runner_success_path}" output_inode) || return 1
    checkpoint_sha=$(read_journal_value \
        "${runner_success_path}" checkpoint_sha256) || return 1
    checkpoint_device=$(read_journal_value \
        "${runner_success_path}" checkpoint_device) || return 1
    checkpoint_inode=$(read_journal_value \
        "${runner_success_path}" checkpoint_inode) || return 1
    validate_runner_success "${identifier}" || return 1
    artifact_identity=$(stat -c '%d:%i' -- "${output_artifact}" 2>/dev/null || true)
    if [[ -f ${output_artifact} && ! -L ${output_artifact} \
        && ${artifact_identity} == "${output_device}:${output_inode}" ]]; then
        evidence_source=${output_artifact}
    elif [[ -f ${final} && ! -L ${final} ]]; then
        evidence_source=${final}
    else
        return 1
    fi
    receipt_target=${final}.root-cleanup
    publish_hardlink_once "${done_path}" "${receipt_target}" 0 || return 1
    if [[ ${evidence_source} == "${output_artifact}" ]]; then
        publish_hardlink_once \
            "${output_artifact}" "${final}" 1 \
            "${output_device}" "${output_inode}" 444 "${output_sha}" \
            "${partial_output_publish_path}" output || return 1
    else
        publish_hardlink_once \
            "${final}" "${final}" 0 \
            "${output_device}" "${output_inode}" 444 "${output_sha}" \
            "${partial_output_publish_path}" output \
            "${output_artifact}" "${final}" || return 1
    fi
    validate_runner_success "${identifier}" || return 1

    checkpoint_source=${checkpoint_artifact}
    final_checkpoint=${final}.runner.complete.jsonl
    checkpoint_identity=$(stat -c '%d:%i' -- "${checkpoint_source}" 2>/dev/null || true)
    if [[ -f ${checkpoint_source} && ! -L ${checkpoint_source} \
        && ${checkpoint_identity} == "${checkpoint_device}:${checkpoint_inode}" ]]; then
        publish_hardlink_once \
            "${checkpoint_source}" "${final_checkpoint}" 1 \
            "${checkpoint_device}" "${checkpoint_inode}" 400 \
            "${checkpoint_sha}" "${partial_checkpoint_publish_path}" \
            checkpoint || return 1
    elif [[ ! -f ${final_checkpoint} || -L ${final_checkpoint} ]]; then
        return 1
    else
        publish_hardlink_once \
            "${final_checkpoint}" "${final_checkpoint}" 0 \
            "${checkpoint_device}" "${checkpoint_inode}" 400 \
            "${checkpoint_sha}" "${partial_checkpoint_publish_path}" \
            checkpoint "${checkpoint_artifact}" "${final_checkpoint}" || return 1
    fi
    validate_runner_success "${identifier}"
}

write_legacy_unqualified_receipt() {
    local identifier=$1 legacy_path metadata payload
    legacy_path=${journal_root}/${identifier}.schema1-unqualified
    payload=$(printf '%s\n' \
        'schema_version=2' \
        "run_id=${identifier}" \
        'request=HISTORICAL_ABORT' \
        'cleanup=passed' \
        'qualified_cleanup=0' \
        'legacy_runner_success_schema=1') || return 1
    if [[ -e ${legacy_path} || -L ${legacy_path} ]]; then
        [[ -f ${legacy_path} && ! -L ${legacy_path} ]] || return 1
        metadata=$(stat -c '%u:%g:%a:%h:%F' -- "${legacy_path}") || return 1
        [[ ${metadata} == '0:0:400:1:regular file' \
            && $(read_journal_value "${legacy_path}" schema_version) == 2 \
            && $(read_journal_value "${legacy_path}" run_id) == "${identifier}" \
            && $(read_journal_value "${legacy_path}" qualified_cleanup) == 0 \
            && $(read_journal_value "${legacy_path}" legacy_runner_success_schema) == 1 ]]
        return
    fi
    write_journal_once "${legacy_path}" "${payload}"
}

recover_incomplete_runs() {
    local intent identifier recovered_failed=0 success_schema intent_schema
    shopt -s nullglob
    for intent in "${journal_root}"/*.intent; do
        identifier=$(basename -- "${intent}" .intent)
        if ! validate_intent "${intent}" "${identifier}"; then
            echo "invalid lmyzmail benchmark recovery intent: ${intent}" >&2
            recovered_failed=1
            continue
        fi
        intent_schema=$(read_journal_value "${intent}" schema_version) || {
            recovered_failed=1
            continue
        }
        if ! cleanup_run_resources "${identifier}" 1; then
            recovered_failed=1
            continue
        fi
        if [[ ${intent_schema} == 1 ]]; then
            write_legacy_unqualified_receipt "${identifier}" || recovered_failed=1
            retain_unqualified_artifacts "${identifier}" || recovered_failed=1
            continue
        fi
        success_schema=missing
        if [[ -f ${runner_success_path} && ! -L ${runner_success_path} ]]; then
            success_schema=$(read_journal_value \
                "${runner_success_path}" schema_version || true)
        fi
        if [[ ${success_schema} != missing && ${success_schema} != 2 ]]; then
            recovered_failed=1
            continue
        fi
        write_cleanup_receipt "${identifier}" RECOVERY "${cleanup_lazy_used}" 1 \
            || recovered_failed=1
        if [[ ${success_schema} == 2 && -f ${runner_success_path} \
            && $(read_journal_value "${done_path}" qualified_cleanup) == 1 ]]; then
            publish_provisional "${identifier}" || recovered_failed=1
        else
            retain_unqualified_artifacts "${identifier}" || recovered_failed=1
        fi
    done
    shopt -u nullglob
    return "${recovered_failed}"
}

write_subtree_control() {
    local path=$1 controller=$2
    printf '+%s\n' "${controller}" >"${path}"
}

enable_controller_monotonic() {
    local group=$1 controller=$2 control
    control=${group}/cgroup.subtree_control
    if grep -qw -- "${controller}" "${control}"; then
        return 0
    fi
    if write_subtree_control "${control}" "${controller}"; then
        return 0
    fi
    grep -qw -- "${controller}" "${control}"
}

enable_persistent_controllers() {
    local controller
    for controller in cpuset cpu io memory pids; do
        enable_controller_monotonic "${cgroup_root}" "${controller}"
    done
    if [[ ! -d ${persistent_group} ]]; then
        mkdir -- "${persistent_group}"
    fi
    if [[ ! -d ${housekeeping_group} ]]; then
        mkdir -- "${housekeeping_group}"
    fi
    printf '%s\n' "${root_cpus}" >"${persistent_group}/cpuset.cpus"
    printf '%s\n' "${root_mems}" >"${persistent_group}/cpuset.mems"
    printf '%s\n' "${housekeeping_cpus}" >"${housekeeping_group}/cpuset.cpus"
    printf '%s\n' "${root_mems}" >"${housekeeping_group}/cpuset.mems"
    for controller in cpuset cpu io memory pids; do
        enable_controller_monotonic "${persistent_group}" "${controller}"
    done
}

stage_checkpoint() {
    local stage=$1 target=${LMYZMAIL_BENCHMARK_TEST_CRASH_AFTER:-}
    [[ ${LMYZMAIL_BENCHMARK_TEST_MODE:-0} == 1 ]] || return 0
    case ${target} in
        launcher:${stage}) kill -KILL -- "$$" ;;
        watchdog:${stage})
            [[ -n ${watchdog_pid} ]]
            kill -KILL -- "${watchdog_pid}"
            wait "${watchdog_pid}" 2>/dev/null || true
            watchdog_pid=
            watchdog_started=0
            return 137
            ;;
    esac
}

filesystem_available_bytes() {
    "${venv_python}" - "$1" <<'PY'
import os
import sys

status = os.statvfs(sys.argv[1])
print(status.f_bavail * status.f_frsize)
PY
}

preflight_image_capacity() {
    local available required
    available=$(filesystem_available_bytes "${image_root}")
    [[ ${available} =~ ^[0-9]+$ ]]
    required=$((image_bytes + host_reserve_bytes))
    if (( available < required )); then
        echo "insufficient host disk for benchmark image and reserve: ${available} < ${required}" >&2
        return 1
    fi
}

verify_launcher_isolation_policy() {
    if (( formal_run == 0 && java_small_baseline_run == 0 )); then
        return 0
    fi
    [[ ${image_bytes} -eq 21474836480 \
        && ${host_reserve_bytes} -ge 10737418240 \
        && ${io_bytes_per_second} -eq 500000000 \
        && ${memory_high_bytes} -eq 7516192768 \
        && ${max_memory_bytes} -eq 8589934592 \
        && ${max_pids} -eq 8192 \
        && ${nofile_limit} -eq 8192 ]]
}

allocate_quota_filesystem() {
    local allocated_blocks allocated_bytes available_after mount_device
    preflight_image_capacity
    backing_device_id=$(findmnt -T "${image_root}" -n -o MAJ:MIN)
    backing_device_id=${backing_device_id//[[:space:]]/}
    [[ ${backing_device_id} =~ ^[0-9]+:[0-9]+$ ]]
    (umask 077; : >"${image_path}")
    fallocate -l "${image_bytes}" -- "${image_path}"
    allocated_blocks=$(stat -c '%b' -- "${image_path}")
    allocated_bytes=$((allocated_blocks * 512))
    if (( allocated_bytes < image_bytes )); then
        echo "benchmark image is sparse: ${allocated_bytes} < ${image_bytes}" >&2
        return 1
    fi
    available_after=$(filesystem_available_bytes "${image_root}")
    [[ ${available_after} =~ ^[0-9]+$ ]]
    if (( available_after < host_reserve_bytes )); then
        echo "benchmark image allocation consumed the host disk reserve" >&2
        return 1
    fi
    stage_checkpoint image-allocated
    loop_device=$(losetup --find --show --direct-io=on "${image_path}")
    [[ ${loop_device} =~ ^/dev/loop[0-9]+$ ]]
    stage_checkpoint loop-attached
    mkfs.ext4 -q -F -m 0 -- "${loop_device}"
    mkdir -- "${quota_mount}"
    mount -t ext4 -o nodev,nosuid,noexec,noatime -- "${loop_device}" "${quota_mount}"
    stage_checkpoint quota-mounted
    mount_device=$(findmnt -M "${quota_mount}" -n -o SOURCE)
    mount_device=${mount_device//[[:space:]]/}
    [[ ${mount_device} == "${loop_device}" ]]
    loop_device_id=$(findmnt -M "${quota_mount}" -n -o MAJ:MIN)
    loop_device_id=${loop_device_id//[[:space:]]/}
    [[ ${loop_device_id} =~ ^[0-9]+:[0-9]+$ ]]
    chown "${benchmark_uid}:${benchmark_gid}" -- "${quota_mount}"
    chmod 0700 -- "${quota_mount}"
}

write_io_max_line() {
    local path=$1 line=$2
    # cgroup control files consume one device command per write(2). A multiline
    # shell redirection is not a valid atomic update for multiple devices.
    printf '%s\n' "${line}" >"${path}"
}

verify_io_max_limit() {
    local path=$1 device=$2 bytes_per_second=$3 line token key value
    local matches=0 rbps= wbps= riops= wiops=
    while IFS= read -r line; do
        [[ ${line} == "${device} "* ]] || continue
        ((matches += 1))
        for token in ${line#* }; do
            [[ ${token} == *=* ]] || return 1
            key=${token%%=*}
            value=${token#*=}
            case ${key} in
            rbps)
                [[ -z ${rbps} ]] || return 1
                rbps=${value}
                ;;
            wbps)
                [[ -z ${wbps} ]] || return 1
                wbps=${value}
                ;;
            riops)
                [[ -z ${riops} ]] || return 1
                riops=${value}
                ;;
            wiops)
                [[ -z ${wiops} ]] || return 1
                wiops=${value}
                ;;
            *) return 1 ;;
            esac
        done
    done <"${path}"
    [[ ${matches} -eq 1 && ${rbps} == "${bytes_per_second}" \
        && ${wbps} == "${bytes_per_second}" \
        && ${riops} == max && ${wiops} == max ]]
}

write_io_max_limit() {
    local path=$1 device=$2 bytes_per_second=$3 expected
    expected="${device} rbps=${bytes_per_second} wbps=${bytes_per_second}"
    write_io_max_line "${path}" "${expected}"
    verify_io_max_limit "${path}" "${device}" "${bytes_per_second}"
}

configure_run_cgroups() {
    mkdir -- "${benchmark_group}" "${harness_group}" \
        "${services_group}" "${workload_group}"
    printf '%s\n' "${root_cpus}" >"${benchmark_group}/cpuset.cpus"
    printf '%s\n' "${root_mems}" >"${benchmark_group}/cpuset.mems"
    printf '+cpuset +cpu +io +memory +pids\n' \
        >"${benchmark_group}/cgroup.subtree_control"
    write_io_max_limit "${benchmark_group}/io.max" \
        "${loop_device_id}" "${io_bytes_per_second}"
    write_io_max_limit "${benchmark_group}/io.max" \
        "${backing_device_id}" "${io_bytes_per_second}"
    verify_io_max_limit "${benchmark_group}/io.max" \
        "${loop_device_id}" "${io_bytes_per_second}"
    verify_io_max_limit "${benchmark_group}/io.max" \
        "${backing_device_id}" "${io_bytes_per_second}"
    printf '%s\n' "${max_pids}" >"${benchmark_group}/pids.max"
    printf '%s\n' "${max_memory_bytes}" >"${benchmark_group}/memory.max"
    printf '%s\n' "${memory_high_bytes}" >"${benchmark_group}/memory.high"
    printf '0\n' >"${benchmark_group}/memory.swap.max"
    printf '%s\n' "${housekeeping_cpus}" >"${harness_group}/cpuset.cpus"
    printf '%s\n' "${root_mems}" >"${harness_group}/cpuset.mems"
    printf '%s\n' "${housekeeping_cpus}" >"${services_group}/cpuset.cpus"
    printf '%s\n' "${root_mems}" >"${services_group}/cpuset.mems"
    printf '%s\n' "${benchmark_cpu}" >"${workload_group}/cpuset.cpus"
    printf '%s\n' "${root_mems}" >"${workload_group}/cpuset.mems"
    printf '100000 100000\n' >"${workload_group}/cpu.max"
    stage_checkpoint cgroups-configured
}

benchmark_proxy_source_sha256() {
    "${venv_python}" - "${repository}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

repository = pathlib.Path(sys.argv[1]).resolve(strict=True)
source_root = (repository / "crates/lmyzmail-benchmark-proxy").resolve(strict=True)
source_files = []
for directory, directory_names, file_names in os.walk(source_root, followlinks=False):
    current = pathlib.Path(directory)
    for name in directory_names:
        if (current / name).is_symlink():
            raise SystemExit("benchmark proxy source tree contains a symlink")
    directory_names[:] = sorted(
        name for name in directory_names if name != "__pycache__"
    )
    for name in sorted(file_names):
        candidate = current / name
        if candidate.is_symlink():
            raise SystemExit("benchmark proxy source tree contains a symlink")
        if candidate.suffix in {".pyc", ".pyo"}:
            continue
        payload = candidate.read_bytes()
        source_files.append(
            {
                "path": candidate.relative_to(repository).as_posix(),
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
source_files.sort(key=lambda entry: entry["path"])
canonical = json.dumps(
    source_files, sort_keys=True, separators=(",", ":")
).encode()
print(hashlib.sha256(canonical).hexdigest())
PY
}

generate_proxy_attestation() {
    local runner_sha source_sha generated
    [[ -x ${proxy_binary} ]] || return 1
    runner_sha=$(sha256sum -- "${runner}" | awk '{print $1}') || return 1
    source_sha=$(benchmark_proxy_source_sha256) || return 1
    generated=$(
        (
            printf '%s\n' "${BASHPID}" >"${harness_group}/cgroup.procs"
            # Match the workload's private Linux loopback topology. WSL mirrored
            # networking can route host-namespace 127.0.0.1 through Windows.
            exec unshare --net -- bash -ceu '
ip link set dev lo up
exec "$@"
' bash prlimit --nofile="${nofile_limit}:${nofile_limit}" -- \
                "${proxy_binary}" headroom-attest \
                --output-root "${proxy_attestation_root}" \
                --runner-sha256 "${runner_sha}" \
                --source-tree-sha256 "${source_sha}" \
                --cgroup-parent "${benchmark_group}" \
                --process-cgroup "${harness_group}" \
                --benchmark-cpu "${benchmark_cpu}" \
                --calibration-cpus "${housekeeping_cpus}" \
                --io-device "${loop_device_id}" \
                --backing-device "${backing_device_id}" \
                --io-bytes-per-second "${io_bytes_per_second}" \
                --memory-high-bytes "${memory_high_bytes}" \
                --memory-max-bytes "${max_memory_bytes}" \
                --pids-max "${max_pids}" \
                --nofile-soft-and-hard "${nofile_limit}" \
                --minimum-product-headroom-ratio 2.0
        )
    ) || return 1
    proxy_attestation_path=$(sed -n '1p' <<<"${generated}") || return 1
    proxy_attestation_sha256=$(sed -n '2p' <<<"${generated}") || return 1
    [[ -f ${proxy_attestation_path} \
        && ${proxy_attestation_path} == \
            "${proxy_attestation_root}/${proxy_attestation_sha256}.json" \
        && ${proxy_attestation_sha256} =~ ^[0-9a-f]{64}$ ]]
}

create_external_attestation() {
    local proxy_path=${proxy_attestation_path:-}
    local proxy_sha=${proxy_attestation_sha256:-}
    local launcher_sha runner_sha generated
    [[ -n ${proxy_path} && -n ${proxy_sha} && -x ${proxy_binary} ]] || return 1
    launcher_sha=$(sha256sum -- "${launcher}" | awk '{print $1}') || return 1
    runner_sha=$(sha256sum -- "${runner}" | awk '{print $1}') || return 1
    generated=$("${venv_python}" - \
        "${proxy_path}" "${proxy_sha}" "${proxy_attestation_root}" \
        "${attestation_root}" "${launcher_sha}" "${runner_sha}" \
        "${repository}" "${proxy_binary}" \
        "${benchmark_group}" "${harness_group}" \
        "${quota_mount}" "${loop_device_id}" "${backing_device_id}" \
        "${image_bytes}" "${host_reserve_bytes}" "${io_bytes_per_second}" \
        "${memory_high_bytes}" "${max_memory_bytes}" "${max_pids}" "${nofile_limit}" \
        "${benchmark_cpu}" "${housekeeping_cpus}" <<'PY'
import hashlib
import json
import math
import os
import pathlib
import stat
import statistics
import sys
import time

(
    proxy_raw,
    expected_sha,
    proxy_root_raw,
    output_root_raw,
    launcher_sha,
    runner_sha,
    repository_raw,
    proxy_binary_raw,
    benchmark_group_raw,
    harness_group_raw,
    mount_root,
    loop_device,
    backing_device,
    limit_bytes_raw,
    reserve_bytes_raw,
    io_bps_raw,
    memory_high_bytes_raw,
    memory_bytes_raw,
    pids_raw,
    nofile_raw,
    benchmark_cpu_raw,
    housekeeping_cpus,
) = sys.argv[1:]
expected_sha = expected_sha.lower()
if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
    raise SystemExit("proxy attestation SHA-256 is invalid")
proxy_root = pathlib.Path(proxy_root_raw)
path = pathlib.Path(proxy_raw)
if not path.is_absolute() or path.parent != proxy_root or path.name != f"{expected_sha}.json":
    raise SystemExit("proxy attestation is not a direct content-addressed child")
root_meta = proxy_root.lstat()
meta = path.lstat()
if not stat.S_ISDIR(root_meta.st_mode) or root_meta.st_uid != 0 or root_meta.st_gid != 0:
    raise SystemExit("proxy attestation directory is not root-owned")
if root_meta.st_mode & 0o022:
    raise SystemExit("proxy attestation directory is writable by non-root")
if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0:
    raise SystemExit("proxy attestation is not root-owned")
if meta.st_mode & 0o222 or meta.st_nlink != 1:
    raise SystemExit("proxy attestation is mutable or multiply linked")
payload = path.read_bytes()
if hashlib.sha256(payload).hexdigest() != expected_sha:
    raise SystemExit("proxy attestation content hash changed")
source = json.loads(payload)
if source.get("schema_version") != 1 or source.get("profile") != "lmyzmail-smtp-proxy-headroom-v1":
    raise SystemExit("proxy attestation profile changed")
proxy = source.get("proxy_headroom")
if not isinstance(proxy, dict) or proxy.get("passed") is not True:
    raise SystemExit("proxy attestation did not pass")
if proxy.get("runner_sha256") != runner_sha:
    raise SystemExit("proxy attestation runner hash changed")
repository = pathlib.Path(repository_raw).resolve(strict=True)
proxy_binary = pathlib.Path(proxy_binary_raw).resolve(strict=True)
if not proxy_binary.is_file() or not proxy_binary.is_relative_to(repository):
    raise SystemExit("benchmark proxy binary path is invalid")
proxy_binary_sha = hashlib.sha256(proxy_binary.read_bytes()).hexdigest()
source_root = (repository / "crates/lmyzmail-benchmark-proxy").resolve(strict=True)
source_files = []
for directory, directory_names, file_names in os.walk(source_root, followlinks=False):
    current = pathlib.Path(directory)
    for name in directory_names:
        candidate = current / name
        if candidate.is_symlink():
            raise SystemExit("benchmark proxy source tree contains a symlink")
    directory_names[:] = sorted(
        name for name in directory_names if name != "__pycache__"
    )
    for name in sorted(file_names):
        candidate = current / name
        if candidate.is_symlink():
            raise SystemExit("benchmark proxy source tree contains a symlink")
        if candidate.suffix in {".pyc", ".pyo"}:
            continue
        payload_bytes = candidate.read_bytes()
        source_files.append(
            {
                "path": candidate.relative_to(repository).as_posix(),
                "bytes": len(payload_bytes),
                "sha256": hashlib.sha256(payload_bytes).hexdigest(),
            }
        )
source_files.sort(key=lambda entry: entry["path"])
source_canonical = json.dumps(
    source_files, sort_keys=True, separators=(",", ":")
).encode()
proxy_source_sha = hashlib.sha256(source_canonical).hexdigest()
if proxy.get("binary_sha256") != proxy_binary_sha:
    raise SystemExit("proxy attestation binary hash changed")
if proxy.get("source_tree_sha256") != proxy_source_sha:
    raise SystemExit("proxy attestation source-tree hash changed")

now = int(time.time())
started = source.get("started_at_unix_seconds")
completed = source.get("completed_at_unix_seconds")
if (
    isinstance(started, bool)
    or not isinstance(started, int)
    or isinstance(completed, bool)
    or not isinstance(completed, int)
    or started > completed
    or completed > now
    or now - completed > 15 * 60
):
    raise SystemExit("proxy attestation is stale or has an invalid time window")
benchmark_group = pathlib.Path(benchmark_group_raw).resolve(strict=True)
harness_group = pathlib.Path(harness_group_raw).resolve(strict=True)
io_max_payload = (benchmark_group / "io.max").read_bytes()
io_max_lines = sorted(
    line.strip() for line in io_max_payload.decode("ascii").splitlines() if line.strip()
)
def io_max_lines_match_fixed_limits(lines, devices, bytes_per_second):
    if not isinstance(lines, list) or len(lines) != len(devices):
        return False
    seen = set()
    for line in lines:
        if not isinstance(line, str):
            return False
        fields = line.split()
        if not fields or fields[0] not in devices or fields[0] in seen:
            return False
        seen.add(fields[0])
        settings = {}
        for field in fields[1:]:
            if "=" not in field:
                return False
            key, value = field.split("=", 1)
            if key in settings or key not in {"rbps", "wbps", "riops", "wiops"}:
                return False
            settings[key] = value
        if settings.get("rbps") != str(bytes_per_second):
            return False
        if settings.get("wbps") != str(bytes_per_second):
            return False
        if (settings.get("riops"), settings.get("wiops")) not in (
            (None, None),
            ("max", "max"),
        ):
            return False
    return seen == devices

environment = proxy.get("environment")
if not isinstance(environment, dict):
    raise SystemExit("proxy attestation environment is missing")
environment_passed = (
    environment.get("host_boot_id")
    == pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    and environment.get("benchmark_cpu") == int(benchmark_cpu_raw)
    and environment.get("calibration_cpus") == housekeeping_cpus
    and environment.get("cgroup_parent") == str(benchmark_group)
    and environment.get("process_cgroup") == str(harness_group)
    and environment.get("cpuset_cpus_effective") == housekeeping_cpus
    and environment.get("io_bytes_per_second_per_device") == int(io_bps_raw)
    and environment.get("io_device") == loop_device
    and environment.get("backing_device") == backing_device
    and environment.get("io_max_lines") == io_max_lines
    and io_max_lines_match_fixed_limits(
        io_max_lines,
        {loop_device, backing_device},
        int(io_bps_raw),
    )
    and environment.get("io_max_sha256")
    == hashlib.sha256(io_max_payload).hexdigest()
    and environment.get("memory_max_bytes") == int(memory_bytes_raw)
    and environment.get("memory_swap_max_bytes") == 0
    and environment.get("pids_max") == int(pids_raw)
    and environment.get("nofile_soft_and_hard") == int(nofile_raw)
    and environment.get("nofile_required") == 4 * 1500 + 512
    and environment.get("nofile_reserve") == 512
    and int(nofile_raw) >= environment.get("nofile_required", 2**63)
)
if not environment_passed:
    raise SystemExit("proxy attestation environment differs from this formal topology")

def canonical_sha(value):
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(payload).hexdigest()

def proxy_memory_evidence_passed(value):
    fields = (
        value.get("pump_buffer_bytes"),
        value.get("configured_max_connections"),
        value.get("backend_reply_block_limit_bytes"),
        value.get("accounted_backend_reply_buffer_bytes"),
        value.get("memory_permit_quantum_bytes"),
        value.get("memory_budget_bytes"),
        value.get("usable_memory_budget_bytes"),
        value.get("required_memory_budget_bytes"),
        value.get("memory_budget_headroom_bytes"),
        value.get("accounted_connection_bytes"),
        value.get("observer_round_reserve_bytes"),
        value.get("control_runtime_reserve_bytes"),
    )
    if any(isinstance(field, bool) or not isinstance(field, int) for field in fields):
        return False
    (
        pump_buffer_bytes,
        configured_max_connections,
        block_limit_bytes,
        accounted_reply_buffer_bytes,
        permit_quantum_bytes,
        memory_budget_bytes,
        usable_memory_budget_bytes,
        required_memory_budget_bytes,
        memory_budget_headroom_bytes,
        accounted_connection_bytes,
        observer_round_reserve_bytes,
        control_runtime_reserve_bytes,
    ) = fields
    positive_fields = fields[:8] + fields[9:]
    if any(field <= 0 for field in positive_fields) or memory_budget_headroom_bytes < 0:
        return False
    expected_reply_buffer_bytes = 1 << (block_limit_bytes - 1).bit_length()
    expected_usable_budget_bytes = (
        memory_budget_bytes // permit_quantum_bytes * permit_quantum_bytes
    )
    expected_required_budget_bytes = (
        accounted_connection_bytes * configured_max_connections
        + observer_round_reserve_bytes
        + control_runtime_reserve_bytes
    )
    return (
        pump_buffer_bytes == 64 * 1024
        and block_limit_bytes == 128 * 1024
        and accounted_reply_buffer_bytes == expected_reply_buffer_bytes
        and permit_quantum_bytes == 64 * 1024
        and accounted_connection_bytes % permit_quantum_bytes == 0
        and observer_round_reserve_bytes % permit_quantum_bytes == 0
        and control_runtime_reserve_bytes % permit_quantum_bytes == 0
        and accounted_connection_bytes
        >= 2 * pump_buffer_bytes + accounted_reply_buffer_bytes
        and usable_memory_budget_bytes == expected_usable_budget_bytes
        and required_memory_budget_bytes == expected_required_budget_bytes
        and memory_budget_headroom_bytes
        == usable_memory_budget_bytes - required_memory_budget_bytes
        and memory_budget_headroom_bytes >= 0
    )

expected_tiers = {
    "1KB": (1024, 250_000, 1500),
    "10KB": (10 * 1024, 250_000, 1000),
    "10MB": (10 * 1024 * 1024, 2000, 80),
}
expected_gate_shapes = {
    "1KB": (250_000, 1500),
    "10KB": (250_000, 1000),
    "10MB": (2_000, 20),
}
calibration_cpu_set = set()
for field in housekeeping_cpus.split(","):
    bounds = field.split("-")
    start, end = (int(bounds[0]), int(bounds[-1]))
    calibration_cpu_set.update(range(start, end + 1))
expected_runtime_topology = {
    "synthetic_worker_threads": 1,
    "proxy_worker_threads": min(8, len(calibration_cpu_set)),
    "separate_proxy_runtime": True,
}
tiers = proxy.get("tiers")
if not isinstance(tiers, dict) or set(tiers) != set(expected_tiers):
    raise SystemExit("proxy attestation tier set changed")
calibration_hashes = {}
observed_peak_connections = 0
for label, (message_bytes, messages, concurrency) in expected_tiers.items():
    tier = tiers[label]
    if not isinstance(tier, dict):
        raise SystemExit(f"proxy tier {label} is invalid")
    raw = tier.get("raw_calibration")
    if not isinstance(raw, dict):
        raise SystemExit(f"proxy tier {label} omitted raw calibration")
    raw_sha = canonical_sha(raw)
    gate = tier.get("gate_overhead_calibration")
    gate_messages, gate_concurrency = expected_gate_shapes[label]
    if not isinstance(gate, dict):
        raise SystemExit(f"proxy tier {label} omitted gate calibration")
    expected_gate_binding = {
        "common": {
            "runner_sha256": runner_sha,
            "binary_sha256": proxy_binary_sha,
            "source_tree_sha256": proxy_source_sha,
            "host_boot_id": environment["host_boot_id"],
            "benchmark_cpu": environment["benchmark_cpu"],
            "calibration_cpus": environment["calibration_cpus"],
            "cgroup_parent": environment["cgroup_parent"],
            "process_cgroup": environment["process_cgroup"],
            "io_max_sha256": environment["io_max_sha256"],
            "nofile_soft_and_hard": environment["nofile_soft_and_hard"],
        },
        "tier": label,
        "message_bytes": message_bytes,
        "messages": gate_messages,
        "concurrency": gate_concurrency,
    }
    gate_sequence = ["off", "on", "on", "off", "on", "off", "off", "on"]
    off_rounds = gate.get("off_rounds")
    on_rounds = gate.get("on_rounds")
    if not isinstance(off_rounds, list) or not isinstance(on_rounds, list):
        raise SystemExit(f"proxy tier {label} gate rounds are invalid")
    gate_rates = {"off": [], "on": []}
    gate_timings = []
    for mode, rounds in (("off", off_rounds), ("on", on_rounds)):
        if len(rounds) != 4:
            raise SystemExit(f"proxy tier {label} gate round count changed")
        expected_indexes = [
            index for index, value in enumerate(gate_sequence) if value == mode
        ]
        for ordinal, round_ in enumerate(rounds):
            measurement = round_.get("measurement")
            gate_observer = round_.get("observer")
            gate_proxy = round_.get("proxy")
            if not all(
                isinstance(value, dict)
                for value in (measurement, gate_observer, gate_proxy)
            ):
                raise SystemExit(f"proxy tier {label} gate proof is incomplete")
            duration_ns = measurement.get("duration_ns")
            rate = measurement.get("messages_per_second")
            persistence = gate_observer.get("persistence_gate")
            if (
                isinstance(duration_ns, bool)
                or not isinstance(duration_ns, int)
                or duration_ns <= 0
                or isinstance(rate, bool)
                or not isinstance(rate, (int, float))
                or not math.isfinite(rate)
                or rate <= 0
                or not math.isclose(rate, gate_messages * 1_000_000_000 / duration_ns)
                or measurement.get("messages") != gate_messages
                or measurement.get("message_bytes") != message_bytes
                or isinstance(measurement.get("process_scheduled_cpu_ns"), bool)
                or not isinstance(measurement.get("process_scheduled_cpu_ns"), int)
                or measurement.get("process_scheduled_cpu_ns") < 0
                or round_.get("mode") != mode
                or round_.get("mode_ordinal") != ordinal
                or round_.get("sequence_index") != expected_indexes[ordinal]
                or gate_observer.get("qualification") is not True
                or gate_observer.get("expected") != gate_messages
                or gate_observer.get("verified") != gate_messages
                or gate_observer.get("missing") != 0
                or gate_observer.get("duplicates") != 0
                or not isinstance(persistence, dict)
                or persistence.get("required") is (mode == "off")
                or persistence.get("qualified") is not True
                or gate_proxy.get("failed_connections") != 0
                or gate_proxy.get("active_connections") != 0
                or not proxy_memory_evidence_passed(gate_proxy)
            ):
                raise SystemExit(f"proxy tier {label} gate round did not qualify")
            gate_rates[mode].append(rate)
            if mode == "on":
                triggered = persistence.get("triggered_at_proxy_monotonic_ns")
                released = persistence.get("release_received_at_proxy_monotonic_ns")
                forwarding_started = persistence.get(
                    "forwarding_started_at_proxy_monotonic_ns"
                )
                forwarding_completed = persistence.get(
                    "forwarding_completed_at_proxy_monotonic_ns"
                )
                gate_hold_ns = persistence.get("gate_hold_ns")
                timing_fields = (
                    triggered,
                    released,
                    forwarding_started,
                    forwarding_completed,
                    gate_hold_ns,
                )
                if (
                    any(
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or value < 0
                        for value in timing_fields
                    )
                    or not triggered <= released <= forwarding_started <= forwarding_completed
                    or gate_hold_ns != released - triggered
                    or persistence.get("proxy_clock_domain")
                    != "observer_origin_elapsed"
                    or persistence.get("status") != "forwarded"
                ):
                    raise SystemExit(f"proxy tier {label} gate timing is invalid")
                snapshot = persistence.get("snapshot")
                if (
                    not isinstance(snapshot, dict)
                    or snapshot.get("clock_id") != "CLOCK_MONOTONIC"
                    or snapshot.get("snapshot_started_monotonic_ns") != 1
                    or snapshot.get("snapshot_completed_monotonic_ns") != 2
                    or snapshot.get("postgres_query_duration_ns") != 0
                    or snapshot.get("maildir_snapshot_duration_ns") != 0
                    or snapshot.get("transaction_isolation") != "repeatable_read"
                    or snapshot.get("transaction_read_only") is not True
                    or snapshot.get("postgres_before_rows") != 0
                    or snapshot.get("postgres_rows") != gate_messages
                    or snapshot.get("postgres_expected_rows") != gate_messages
                    or snapshot.get("postgres_row_delta") != gate_messages
                    or snapshot.get("expected_messages") != gate_messages
                    or snapshot.get("maildir_atomic_rename_publications")
                    != gate_messages
                    or snapshot.get("qualified") is not True
                ):
                    raise SystemExit(
                        f"proxy tier {label} synthetic gate snapshot is invalid"
                    )
                gate_timings.append(
                    (
                        gate_hold_ns / duration_ns,
                        forwarding_started - released,
                        forwarding_completed - forwarding_started,
                    )
                )
    off_median = statistics.median(gate_rates["off"])
    on_median = statistics.median(gate_rates["on"])
    off_spread = (max(gate_rates["off"]) - min(gate_rates["off"])) / off_median
    on_spread = (max(gate_rates["on"]) - min(gate_rates["on"])) / on_median
    paired = [gate_rates["on"][index] / gate_rates["off"][index] for index in range(4)]
    maximum_gate_hold_fraction = max(value[0] for value in gate_timings)
    maximum_release_to_forwarding_ns = max(value[1] for value in gate_timings)
    maximum_forwarding_ns = max(value[2] for value in gate_timings)
    if not (
        gate.get("schema_version") == 3
        and canonical_sha(gate.get("runtime_topology"))
        == canonical_sha(expected_runtime_topology)
        and gate.get("profile") == "lmyzmail-persistence-gate-overhead-calibration-v3"
        and gate.get("qualification_basis") == "direct-gate-timing"
        and gate.get("synthetic_no_postgres_or_maildir") is True
        and gate.get("messages") == gate_messages
        and gate.get("message_bytes") == message_bytes
        and gate.get("concurrency") == gate_concurrency
        and gate.get("rounds_per_mode") == 4
        and gate.get("sequence") == gate_sequence
        and gate.get("binding") == expected_gate_binding
        and gate.get("maximum_round_spread") == 0.01
        and gate.get("minimum_median_on_to_off_ratio") == 0.995
        and gate.get("minimum_paired_on_to_off_ratio") == 0.99
        and gate.get("maximum_gate_hold_fraction") == 0.01
        and gate.get("maximum_release_to_forwarding_ns") == 5_000_000
        and gate.get("maximum_forwarding_ns") == 1_000_000
        and math.isclose(
            gate.get("off_median", {}).get("messages_per_second", -1),
            off_median,
        )
        and math.isclose(
            gate.get("on_median", {}).get("messages_per_second", -1),
            on_median,
        )
        and math.isclose(gate.get("off_round_spread", -1), off_spread)
        and math.isclose(gate.get("on_round_spread", -1), on_spread)
        and math.isclose(gate.get("median_on_to_off_ratio", -1), on_median / off_median)
        and isinstance(gate.get("paired_on_to_off_ratios"), list)
        and len(gate["paired_on_to_off_ratios"]) == 4
        and all(
            math.isclose(recorded, observed)
            for recorded, observed in zip(
                gate.get("paired_on_to_off_ratios", ()), paired, strict=True
            )
        )
        and math.isclose(
            gate.get("observed_maximum_gate_hold_fraction", -1),
            maximum_gate_hold_fraction,
        )
        and gate.get("observed_maximum_release_to_forwarding_ns")
        == maximum_release_to_forwarding_ns
        and gate.get("observed_maximum_forwarding_ns") == maximum_forwarding_ns
        and maximum_gate_hold_fraction <= 0.01
        and maximum_release_to_forwarding_ns <= 5_000_000
        and maximum_forwarding_ns <= 1_000_000
        and gate.get("qualification") is True
    ):
        raise SystemExit(f"proxy tier {label} gate qualification did not recompute")
    gate_sha = canonical_sha(gate)
    calibration_hashes[label] = canonical_sha(
        {
            "raw_calibration_sha256": raw_sha,
            "gate_overhead_calibration_sha256": gate_sha,
        }
    )
    direct_rounds = raw.get("direct_rounds")
    proxied_rounds = raw.get("proxied_rounds")
    if not isinstance(direct_rounds, list) or not isinstance(proxied_rounds, list):
        raise SystemExit(f"proxy tier {label} round vectors are invalid")
    direct_rates = [round_["messages_per_second"] for round_ in direct_rounds]
    proxied_rates = [round_["messages_per_second"] for round_ in proxied_rounds]
    all_rates = direct_rates + proxied_rates
    if any(
        isinstance(rate, bool)
        or not isinstance(rate, (int, float))
        or not math.isfinite(rate)
        or rate <= 0
        for rate in all_rates
    ):
        raise SystemExit(f"proxy tier {label} contains invalid rates")
    direct_median = statistics.median(direct_rates)
    proxied_median = statistics.median(proxied_rates)
    direct_spread = (max(direct_rates) - min(direct_rates)) / direct_median
    proxied_spread = (max(proxied_rates) - min(proxied_rates)) / proxied_median
    observer = raw.get("observer")
    control_proxy = raw.get("control_proxy")
    raw_proxy = raw.get("proxy")
    if not all(
        isinstance(value, dict) for value in (observer, control_proxy, raw_proxy)
    ):
        raise SystemExit(f"proxy tier {label} raw proof is incomplete")
    expected_observed = messages * 4
    expected_connections = concurrency * 4
    raw_passed = (
        raw.get("schema_version") == 5
        and canonical_sha(raw.get("runtime_topology"))
        == canonical_sha(expected_runtime_topology)
        and raw.get("control_topology") == "bounded-unobserved-proxy"
        and raw.get("observed_topology") == "bounded-observing-proxy"
        and raw.get("equal_tcp_hop_topology") is True
        and raw.get("mode") == "data"
        and raw.get("messages") == messages
        and raw.get("message_bytes") == message_bytes
        and raw.get("concurrency") == concurrency
        and raw.get("rounds_per_arm") == 4
        and raw.get("sequence")
        == ["direct", "proxied", "proxied", "direct"] * 2
        and len(direct_rounds) == len(proxied_rounds) == 4
        and all(
            round_.get("messages") == messages
            and round_.get("message_bytes") == message_bytes
            for round_ in direct_rounds + proxied_rounds
        )
        and math.isclose(
            raw.get("direct", {}).get("messages_per_second", -1),
            direct_median,
            rel_tol=1e-9,
            abs_tol=1e-9,
        )
        and math.isclose(
            raw.get("proxied", {}).get("messages_per_second", -1),
            proxied_median,
            rel_tol=1e-9,
            abs_tol=1e-9,
        )
        and math.isclose(
            raw.get("proxy_to_direct_ratio", -1),
            proxied_median / direct_median,
            rel_tol=1e-9,
            abs_tol=1e-9,
        )
        and raw.get("proxy_to_direct_ratio", 0) >= 0.90
        and raw.get("minimum_proxy_to_direct_ratio") == 0.90
        and isinstance(raw.get("estimated_observer_cpu_ns_per_message"), (int, float))
        and not isinstance(raw.get("estimated_observer_cpu_ns_per_message"), bool)
        and math.isfinite(raw["estimated_observer_cpu_ns_per_message"])
        and raw["estimated_observer_cpu_ns_per_message"] >= 0
        and raw.get("maximum_round_spread") == 0.20
        and math.isclose(raw.get("direct_round_spread", -1), direct_spread)
        and math.isclose(raw.get("proxied_round_spread", -1), proxied_spread)
        and direct_spread <= 0.20
        and proxied_spread <= 0.20
        and observer.get("qualification") is True
        and observer.get("expected") == expected_observed
        and observer.get("verified") == expected_observed
        and observer.get("missing") == 0
        and observer.get("duplicates") == 0
        and control_proxy.get("accepted_connections") == expected_connections
        and control_proxy.get("completed_connections") == expected_connections
        and control_proxy.get("failed_connections") == 0
        and control_proxy.get("active_connections") == 0
        and control_proxy.get("peak_connections") == concurrency
        and proxy_memory_evidence_passed(control_proxy)
        and raw_proxy.get("accepted_connections") == expected_connections
        and raw_proxy.get("completed_connections") == expected_connections
        and raw_proxy.get("failed_connections") == 0
        and raw_proxy.get("active_connections") == 0
        and raw_proxy.get("peak_connections") == concurrency
        and proxy_memory_evidence_passed(raw_proxy)
        and raw.get("qualification") is True
    )
    tier_passed = (
        tier.get("message_bytes") == message_bytes
        and tier.get("messages_per_round") == messages
        and tier.get("concurrency") == concurrency
        and tier.get("rounds_per_arm") == 4
        and tier.get("raw_calibration_schema_version") == 5
        and tier.get("raw_calibration_sha256") == raw_sha
        and tier.get("gate_overhead_calibration_schema_version") == 3
        and tier.get("gate_overhead_calibration_sha256") == gate_sha
        and math.isclose(
            tier.get("sustained_messages_per_second", -1),
            min(proxied_rates),
            rel_tol=1e-9,
            abs_tol=1e-9,
        )
        and tier.get("passed") is True
        and raw_passed
    )
    if not tier_passed:
        raise SystemExit(f"proxy tier {label} raw qualification did not recompute")
    observed_peak_connections = max(
        observed_peak_connections, int(raw_proxy.get("peak_connections", -1))
    )
if (
    proxy.get("calibration_bundle_sha256") != canonical_sha(calibration_hashes)
    or proxy.get("max_active_connections") != observed_peak_connections
    or observed_peak_connections < 1500
    or proxy.get("minimum_product_headroom_ratio") != 2.0
    or proxy.get("semantic_transparency_passed") is not True
    or proxy.get("passed") is not True
):
    raise SystemExit("proxy aggregate headroom proof did not recompute")
proxy = dict(proxy)
proxy["attestation_started_at_unix_seconds"] = started
proxy["attestation_completed_at_unix_seconds"] = completed
isolation_policy = {
    "schema_version": 1,
    "profile": "lmyzmail-smtp-throughput-formal-isolation-v1",
    "image_bytes": 20 * 1024**3,
    "minimum_host_reserve_bytes": 10 * 1024**3,
    "io_bytes_per_second_per_device": 500_000_000,
    "io_devices": "loop-and-backing",
    "memory_high_bytes": 7 * 1024**3,
    "memory_max_bytes": 8 * 1024**3,
    "memory_swap_max_bytes": 0,
    "pids_max": 8192,
    "nofile_soft_and_hard": 8192,
    "application_cpu_count": 1,
    "housekeeping_excludes_application_cpu": True,
    "cgroup_control_owner": "host-root",
    "runtime_cgroupfs": "read-only-bind-mount",
    "runner_process": "non-dumpable-without-CAP_SYS_PTRACE",
    "role_topology": {
        "application": "workload",
        "postgres": "services",
        "redis": "services",
        "runner_and_proxy": "harness",
        "watchdog_and_supervisor": "persistent-housekeeping",
    },
}
isolation_canonical = json.dumps(
    isolation_policy, sort_keys=True, separators=(",", ":")
).encode()
observed_policy = {
    "image_bytes": int(limit_bytes_raw),
    "host_reserve_bytes": int(reserve_bytes_raw),
    "io_bytes_per_second_per_device": int(io_bps_raw),
    "memory_high_bytes": int(memory_high_bytes_raw),
    "memory_max_bytes": int(memory_bytes_raw),
    "pids_max": int(pids_raw),
    "nofile_soft_and_hard": int(nofile_raw),
    "application_cpu": int(benchmark_cpu_raw),
    "housekeeping_cpus": housekeeping_cpus,
    "root_only_cgroup_migration": True,
}
policy_passed = (
    observed_policy["image_bytes"] == isolation_policy["image_bytes"]
    and observed_policy["host_reserve_bytes"] >= isolation_policy["minimum_host_reserve_bytes"]
    and observed_policy["io_bytes_per_second_per_device"]
    == isolation_policy["io_bytes_per_second_per_device"]
    and observed_policy["memory_high_bytes"] == isolation_policy["memory_high_bytes"]
    and observed_policy["memory_max_bytes"] == isolation_policy["memory_max_bytes"]
    and observed_policy["pids_max"] == isolation_policy["pids_max"]
    and observed_policy["nofile_soft_and_hard"] == isolation_policy["nofile_soft_and_hard"]
)
if not policy_passed:
    raise SystemExit("launcher isolation policy changed")
value = {
    "schema_version": 1,
    "profile": "lmyzmail-smtp-throughput-external-prerequisites-v1",
    "launcher_sha256": launcher_sha,
    "proxy_headroom": proxy,
    "hard_disk_quota": {
        "passed": True,
        "enforcement": "loopback",
        "limit_bytes": int(limit_bytes_raw),
        "device": loop_device,
        "backing_device": backing_device,
        "mount_root": mount_root,
        "fully_allocated": True,
        "host_reserve_bytes": int(reserve_bytes_raw),
        "ordinary_unmount_required": True,
    },
    "isolation_policy": {
        "expected": isolation_policy,
        "observed": observed_policy,
        "canonical_policy_sha256": hashlib.sha256(isolation_canonical).hexdigest(),
        "passed": policy_passed,
    },
}
output = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
digest = hashlib.sha256(output).hexdigest()
output_root = pathlib.Path(output_root_raw)
output_root.mkdir(mode=0o755, parents=True, exist_ok=True)
target = output_root / f"{digest}.json"
temporary = output_root / f".{digest}.{os.getpid()}.tmp"
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
try:
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(output)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temporary, target)
    directory = os.open(output_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    temporary.unlink(missing_ok=True)
print(target)
print(digest)
PY
) || return 1
    external_attestation_path=$(sed -n '1p' <<<"${generated}") || return 1
    external_attestation_sha256=$(sed -n '2p' <<<"${generated}") || return 1
    [[ -f ${external_attestation_path} \
        && ${external_attestation_path} == "${attestation_root}/${external_attestation_sha256}.json" ]] \
        || return 1
}

start_cgroup_supervisor() {
    local owner_pid=$1 ready_fifo=$2
    exec setpriv --pdeathsig SIGKILL "${venv_python}" -u - \
        "${migration_socket}" "${proc_root}" "${cgroup_root}" "${owner_pid}" \
        "${benchmark_group}" "${harness_group}" "${workload_group}" \
        "${services_group}" >"${ready_fifo}" <<'PY'
import json
import os
import pathlib
import socket
import struct
import sys
import time

(
    socket_raw,
    proc_raw,
    cgroup_raw,
    owner_raw,
    parent_raw,
    harness_raw,
    workload_raw,
    services_raw,
) = sys.argv[1:]
socket_path = pathlib.Path(socket_raw)
proc_root = pathlib.Path(proc_raw)
cgroup_root = pathlib.Path(cgroup_raw)
owner_pid = int(owner_raw)
groups = dict(
    parent=pathlib.Path(parent_raw),
    harness=pathlib.Path(harness_raw),
    application=pathlib.Path(workload_raw),
    postgres=pathlib.Path(services_raw),
    redis=pathlib.Path(services_raw),
)
destinations = dict(application=groups["application"], postgres=groups["postgres"], redis=groups["redis"])
registered = None
assigned = dict()


def process_stat(pid):
    raw = (proc_root / str(pid) / "stat").read_text(encoding="ascii")
    fields = raw[raw.rfind(")") + 2 :].split()
    if len(fields) <= 19:
        raise RuntimeError("short process stat")
    return int(fields[1]), int(fields[19])


def process_cgroup(pid):
    for line in (proc_root / str(pid) / "cgroup").read_text(encoding="ascii").splitlines():
        if line.startswith("0::"):
            return line[3:]
    raise RuntimeError("process has no unified cgroup")


def expected_cgroup(path):
    return "/" + path.relative_to(cgroup_root).as_posix()


def is_descendant(pid, ancestor):
    seen = set()
    while pid > 1 and pid not in seen:
        if pid == ancestor:
            return True
        seen.add(pid)
        pid, _ = process_stat(pid)
    return False


def process_tree(root):
    children = dict()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            parent, _ = process_stat(int(entry.name))
        except (FileNotFoundError, PermissionError, ValueError, RuntimeError):
            continue
        children.setdefault(parent, []).append(int(entry.name))
    pending = [root]
    output = set()
    while pending:
        pid = pending.pop()
        if pid in output:
            continue
        try:
            process_stat(pid)
        except (FileNotFoundError, PermissionError):
            continue
        output.add(pid)
        pending.extend(children.get(pid, ()))
    return output


def send(connection, payload):
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(encoded) > 4096:
        raise RuntimeError("supervisor response exceeds protocol limit")
    connection.sendall(encoded)


def receive(connection):
    connection.settimeout(2.0)
    payload = bytearray()
    while b"\n" not in payload:
        chunk = connection.recv(4096 - len(payload))
        if not chunk:
            raise RuntimeError("incomplete supervisor request")
        payload.extend(chunk)
        if len(payload) >= 4096:
            raise RuntimeError("supervisor request exceeds protocol limit")
    line, trailing = bytes(payload).split(b"\n", 1)
    if trailing.strip():
        raise RuntimeError("multiple supervisor requests on one connection")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise RuntimeError("supervisor request is not an object")
    return value


socket_path.unlink(missing_ok=True)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o622)
    server.listen(16)
    print("READY", flush=True)
    stopping = False
    while not stopping:
        connection, _ = server.accept()
        with connection:
            credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            peer_pid, peer_uid, _ = struct.unpack("3i", credentials)
            try:
                request = receive(connection)
                operation = request.get("operation")
                if operation == "register":
                    if peer_uid != 0 or registered is not None:
                        raise RuntimeError("runner registration is not authorized")
                    runner_pid = int(request["pid"])
                    start_time = int(request["start_time"])
                    if not is_descendant(runner_pid, owner_pid):
                        raise RuntimeError("runner is not a launcher descendant")
                    if process_stat(runner_pid)[1] != start_time:
                        raise RuntimeError("runner start time changed")
                    if process_cgroup(runner_pid) != expected_cgroup(groups["harness"]):
                        raise RuntimeError("runner is outside the harness cgroup")
                    registered = (runner_pid, start_time)
                    send(connection, dict(passed=True, operation="register", pid=runner_pid))
                elif operation == "migrate":
                    if registered is None or peer_pid != registered[0] or peer_uid == 0:
                        raise RuntimeError("migration requester is not the registered runner")
                    if process_stat(peer_pid)[1] != registered[1]:
                        raise RuntimeError("registered runner identity changed")
                    role = request.get("role")
                    if role not in destinations:
                        raise RuntimeError("migration role is invalid")
                    root_pid = int(request["pid"])
                    start_time = int(request["start_time"])
                    if process_stat(root_pid)[1] != start_time or not is_descendant(root_pid, peer_pid):
                        raise RuntimeError("migration root is not a live runner descendant")
                    destination = destinations[role]
                    source_cgroup = expected_cgroup(groups["harness"])
                    destination_cgroup = expected_cgroup(destination)
                    migrated = set()
                    for _ in range(5):
                        if process_stat(root_pid)[1] != start_time:
                            raise RuntimeError("migration root identity changed")
                        for pid in sorted(process_tree(root_pid)):
                            previous = assigned.get(pid)
                            if previous is not None and previous != role:
                                raise RuntimeError("PID was assigned to conflicting roles")
                            try:
                                if process_cgroup(pid) not in (source_cgroup, destination_cgroup):
                                    raise RuntimeError("migration PID escaped before assignment")
                                (destination / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")
                            except (FileNotFoundError, ProcessLookupError):
                                continue
                            assigned[pid] = role
                            migrated.add(pid)
                        time.sleep(0.02)
                    if process_stat(root_pid)[1] != start_time:
                        raise RuntimeError("migration root identity changed")
                    current = process_tree(root_pid)
                    if not current or any(process_cgroup(pid) != destination_cgroup for pid in current):
                        raise RuntimeError("role migration did not converge")
                    send(
                        connection,
                        dict(
                            passed=True,
                            operation="migrate",
                            role=role,
                            root_pid=root_pid,
                            root_start_time=start_time,
                            destination=destination_cgroup,
                            migrated_pids=sorted(migrated),
                        ),
                    )
                elif operation == "stop":
                    if peer_uid != 0:
                        raise RuntimeError("supervisor stop is not authorized")
                    send(connection, dict(passed=True, operation="stop"))
                    stopping = True
                else:
                    raise RuntimeError("unknown supervisor operation")
            except Exception as error:
                try:
                    send(connection, dict(passed=False, error=type(error).__name__, message=str(error)))
                except OSError:
                    pass
finally:
    server.close()
    socket_path.unlink(missing_ok=True)
PY
}

cgroup_supervisor_root_request() {
    local operation=$1 pid=${2:-0} start_time=${3:-0}
    "${venv_python}" - "${migration_socket}" "${operation}" "${pid}" "${start_time}" <<'PY'
import json
import socket
import sys

path, operation, pid_raw, start_raw = sys.argv[1:]
request = dict(operation=operation)
if operation == "register":
    request.update(pid=int(pid_raw), start_time=int(start_raw))
payload = (json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(5.0)
    connection.connect(path)
    connection.sendall(payload)
    response = bytearray()
    while b"\n" not in response:
        chunk = connection.recv(4096 - len(response))
        if not chunk:
            raise SystemExit("cgroup supervisor closed without a response")
        response.extend(chunk)
        if len(response) >= 4096:
            raise SystemExit("cgroup supervisor response exceeded protocol limit")
value = json.loads(bytes(response).split(b"\n", 1)[0])
if value.get("passed") is not True or value.get("operation") != operation:
    raise SystemExit(f"cgroup supervisor rejected {operation}: {value}")
PY
}

watchdog_read_command() {
    local owner_pid=$1 output_name=$2 supervisor_pid=${3:-} input= read_status
    while :; do
        if IFS= read -r -t 1 input; then
            printf -v "${output_name}" '%s' "${input}"
            return 0
        else
            read_status=$?
        fi
        if (( read_status <= 128 )); then
            return 1
        fi
        if ! kill -0 -- "${owner_pid}" 2>/dev/null; then
            return 1
        fi
        if [[ -n ${supervisor_pid} ]] && ! kill -0 -- "${supervisor_pid}" 2>/dev/null; then
            return 1
        fi
    done
}

register_managed_runner() {
    local pid=$1 start_time=$2 extra=${3-}
    [[ -z ${managed_runner_pid} && ${pid} =~ ^[1-9][0-9]*$ \
        && ${start_time} =~ ^[1-9][0-9]*$ && -z ${extra} ]] || return 1
    managed_runner_pid=${pid}
    managed_runner_start_time=${start_time}
}

register_managed_artifacts() {
    local output_device=$1 output_inode=$2 checkpoint_device=$3 checkpoint_inode=$4
    local output_fd_path checkpoint_fd_path output_metadata checkpoint_metadata
    [[ -z ${managed_output_fd} && -z ${managed_checkpoint_fd} \
        && ${output_device} =~ ^[0-9]+$ && ${output_inode} =~ ^[1-9][0-9]*$ \
        && ${checkpoint_device} =~ ^[0-9]+$ \
        && ${checkpoint_inode} =~ ^[1-9][0-9]*$ ]] || return 1
    exec {managed_output_fd}<"${output_artifact}" || return 1
    if ! exec {managed_checkpoint_fd}<"${checkpoint_artifact}"; then
        exec {managed_output_fd}<&-
        managed_output_fd=
        return 1
    fi
    output_fd_path=${proc_root}/${BASHPID}/fd/${managed_output_fd}
    checkpoint_fd_path=${proc_root}/${BASHPID}/fd/${managed_checkpoint_fd}
    [[ -f ${output_fd_path} && -f ${checkpoint_fd_path} ]] || return 1
    output_metadata=$(stat -Lc '%d:%i:%u:%g:%a:%h' \
        -- "${output_fd_path}") || return 1
    checkpoint_metadata=$(stat -Lc '%d:%i:%u:%g:%a:%h' \
        -- "${checkpoint_fd_path}") || return 1
    [[ ${output_metadata} == "${output_device}:${output_inode}:0:0:600:1" \
        && ${checkpoint_metadata} \
        == "${checkpoint_device}:${checkpoint_inode}:0:0:600:1" ]]
}

runner_completion_matches() {
    local pid=$1 start_time=$2 extra=${3-}
    [[ -n ${managed_runner_pid} && ${pid} == "${managed_runner_pid}" \
        && ${start_time} == "${managed_runner_start_time}" && -z ${extra} ]]
}

watchdog_artifacts_match_receipt() {
    local identifier=$1 output_fd=$2 checkpoint_fd=$3 output_metadata checkpoint_metadata
    local expected_output_device expected_output_inode
    local expected_checkpoint_device expected_checkpoint_inode output_fd_path checkpoint_fd_path
    derive_run_paths "${identifier}" || return 1
    [[ -f ${runner_success_path} && ! -L ${runner_success_path} \
        && $(read_journal_value "${runner_success_path}" schema_version) == 2 ]] \
        || return 1
    expected_output_device=$(read_journal_value \
        "${runner_success_path}" output_device) || return 1
    expected_output_inode=$(read_journal_value \
        "${runner_success_path}" output_inode) || return 1
    expected_checkpoint_device=$(read_journal_value \
        "${runner_success_path}" checkpoint_device) || return 1
    expected_checkpoint_inode=$(read_journal_value \
        "${runner_success_path}" checkpoint_inode) || return 1
    output_fd_path=${proc_root}/${BASHPID}/fd/${output_fd}
    checkpoint_fd_path=${proc_root}/${BASHPID}/fd/${checkpoint_fd}
    [[ -f ${output_fd_path} && -f ${checkpoint_fd_path} ]] || return 1
    output_metadata=$(stat -Lc '%d:%i:%u:%g:%a' \
        -- "${output_fd_path}") || return 1
    checkpoint_metadata=$(stat -Lc '%d:%i:%u:%g:%a' \
        -- "${checkpoint_fd_path}") || return 1
    [[ ${output_metadata} \
        == "${expected_output_device}:${expected_output_inode}:0:0:444" \
        && ${checkpoint_metadata} \
        == "${expected_checkpoint_device}:${expected_checkpoint_inode}:0:0:400" ]]
}

root_cleanup_watchdog() {
    local owner_pid=$1 identifier=$2 line= tag= value= identity= extra= fifth=
    local managed_runner_pid= managed_runner_start_time= request=ABORT
    local managed_output_fd= managed_checkpoint_fd=
    local protocol_failed=0 cleanup_failed=0 supervisor_pid= supervisor_ready=
    local artifact_receipt_valid=0 runner_success_valid=0
    local supervisor_fifo=
    trap - EXIT INT TERM HUP
    trap '' PIPE
    derive_run_paths "${identifier}" || return 1
    if [[ ! -e ${proc_root}/${BASHPID}/fd/${benchmark_lock_fd} ]]; then
        echo "benchmark watchdog did not inherit the benchmark lock" >&2
        return 1
    fi
    if ! printf '%s\n' "${BASHPID}" >"${housekeeping_group}/cgroup.procs"; then
        echo "benchmark watchdog could not enter the housekeeping cgroup" >&2
        return 1
    fi
    supervisor_fifo=${migration_socket}.ready
    rm -f -- "${supervisor_fifo}" "${migration_socket}"
    mkfifo -m 0600 -- "${supervisor_fifo}"
    start_cgroup_supervisor "${owner_pid}" "${supervisor_fifo}" &
    supervisor_pid=$!
    if ! IFS= read -r -t 5 supervisor_ready <"${supervisor_fifo}" \
        || [[ ${supervisor_ready} != READY || ! -S ${migration_socket} ]] \
        || ! kill -0 -- "${supervisor_pid}" 2>/dev/null; then
        echo "benchmark cgroup supervisor did not become ready" >&2
        kill -KILL -- "${supervisor_pid}" 2>/dev/null || true
        wait "${supervisor_pid}" 2>/dev/null || true
        rm -f -- "${supervisor_fifo}" "${migration_socket}"
        cleanup_run_resources "${identifier}" 0 || true
        return 1
    fi
    rm -f -- "${supervisor_fifo}"
    if ! printf 'READY %s %s\n' "${BASHPID}" "${identifier}"; then
        echo "benchmark watchdog lost its readiness pipe" >&2
        return 1
    fi
    while watchdog_read_command "${owner_pid}" line "${supervisor_pid}"; do
        tag= value= identity= extra= fifth=
        IFS=' ' read -r tag value identity extra fifth <<<"${line}"
        case ${tag} in
        ARTIFACTS)
            if ! register_managed_artifacts \
                "${value}" "${identity}" "${extra}" "${fifth}"; then
                protocol_failed=1
                break
            fi
            if ! printf 'ARTIFACTS-REGISTERED %s %s %s %s\n' \
                "${value}" "${identity}" "${extra}" "${fifth}"; then
                protocol_failed=1
                break
            fi
            ;;
        RUNNER)
            if [[ -z ${managed_output_fd} || -z ${managed_checkpoint_fd} \
                || -n ${extra} || -n ${fifth} ]] \
                || ! register_managed_runner "${value}" "${identity}" \
                || ! cgroup_supervisor_root_request register "${value}" "${identity}"; then
                protocol_failed=1
                break
            fi
            if ! printf 'REGISTERED %s %s\n' "${value}" "${identity}"; then
                protocol_failed=1
                break
            fi
            ;;
        DONE|STOP|ABORT)
            if [[ -n ${fifth} ]] \
                || ! runner_completion_matches "${value}" "${identity}" "${extra}"; then
                protocol_failed=1
            else
                request=${tag}
            fi
            break
            ;;
        *)
            protocol_failed=1
            break
            ;;
        esac
    done
    if [[ ${request} != DONE && -n ${managed_runner_pid} ]]; then
        signal_registered_runner \
            "${managed_runner_pid}" "${managed_runner_start_time}" INT || true
    fi
    if kill -0 -- "${supervisor_pid}" 2>/dev/null; then
        cgroup_supervisor_root_request stop || protocol_failed=1
        wait "${supervisor_pid}" || protocol_failed=1
    else
        protocol_failed=1
        wait "${supervisor_pid}" 2>/dev/null || true
    fi
    rm -f -- "${supervisor_fifo}" "${migration_socket}"
    if ! cleanup_run_resources "${identifier}" 0; then
        cleanup_failed=1
    else
        if [[ -n ${managed_runner_pid} && -n ${managed_output_fd} \
            && -n ${managed_checkpoint_fd} ]] \
            && watchdog_artifacts_match_receipt \
                "${identifier}" "${managed_output_fd}" "${managed_checkpoint_fd}"; then
            artifact_receipt_valid=1
        fi
        if [[ -n ${managed_runner_pid} ]] \
            && validate_runner_success \
                "${identifier}" "${managed_runner_pid}" "${managed_runner_start_time}"; then
            runner_success_valid=1
        fi
        if (( artifact_receipt_valid != 0 && runner_success_valid != 0 )); then
            request=DONE
        else
            echo "benchmark watchdog qualification failed: " \
                "artifact_receipt_valid=${artifact_receipt_valid} " \
                "runner_success_valid=${runner_success_valid}" >&2
            request=ABORT
        fi
        if ! write_cleanup_receipt \
            "${identifier}" "${request}" 0 0 \
            "${managed_runner_pid}" "${managed_runner_start_time}"; then
            cleanup_failed=1
        elif ! retain_unqualified_artifacts "${identifier}"; then
            cleanup_failed=1
        fi
    fi
    (( protocol_failed == 0 && cleanup_failed == 0 ))
}

wait_for_cleanup_watchdog() {
    local supervised_pid=$1 timeout_pid= completed_pid= wait_status=0
    (
        exec {benchmark_lock_fd}>&-
        exec sleep 60
    ) &
    timeout_pid=$!
    if wait -n -p completed_pid "${supervised_pid}" "${timeout_pid}"; then
        wait_status=0
    else
        wait_status=$?
    fi
    if [[ ${completed_pid} == "${supervised_pid}" ]]; then
        kill -KILL -- "${timeout_pid}" 2>/dev/null || true
        wait "${timeout_pid}" 2>/dev/null || true
        return "${wait_status}"
    fi
    echo "benchmark cleanup watchdog exceeded its bounded cleanup window" >&2
    kill -KILL -- "${supervised_pid}" 2>/dev/null || true
    wait "${supervised_pid}" 2>/dev/null || true
    return 124
}

cleanup() {
    local exit_code=$? cleanup_failed=0 request=ABORT
    trap - EXIT INT TERM HUP
    close_runner_artifact_fds
    if (( cleanup_finalized != 0 )); then
        exit "${exit_code}"
    fi
    if [[ -n ${benchmark_group} && -e ${cgroup_root}/cgroup.procs ]]; then
        printf '%s\n' "$$" >"${cgroup_root}/cgroup.procs" 2>/dev/null || true
    fi
    if [[ -n ${watchdog_control_fd} ]]; then
        if (( runner_registered != 0 )); then
            (( runner_finished != 0 )) && request=DONE
            printf '%s %s %s\n' "${request}" "${runner_pid}" "${runner_start_time}" \
                >&"${watchdog_control_fd}" 2>/dev/null || cleanup_failed=1
        fi
        exec {watchdog_control_fd}>&-
    fi
    if [[ -n ${watchdog_status_fd} ]]; then
        exec {watchdog_status_fd}<&-
    fi
    if (( watchdog_started != 0 )) && [[ -n ${watchdog_pid} ]]; then
        wait_for_cleanup_watchdog "${watchdog_pid}" || cleanup_failed=1
        watchdog_pid=
    elif [[ -n ${run_id} ]]; then
        if cleanup_run_resources "${run_id}" 0; then
            if ! write_cleanup_receipt "${run_id}" ABORT 0 0 \
                || ! retain_unqualified_artifacts "${run_id}"; then
                cleanup_failed=1
            fi
        else
            cleanup_failed=1
        fi
    fi
    if [[ -n ${runner_pid} && ${runner_reaped} -eq 0 ]]; then
        wait "${runner_pid}" 2>/dev/null || true
    fi
    (( cleanup_failed == 0 || exit_code != 0 )) || exit_code=1
    exit "${exit_code}"
}

parse_runner_arguments() {
    local -a input=("$@") output=()
    local index=0 value= smoke=0 seen_output=0 profile=abba target=both tier=all
    local profiler_messages= seen_profiler_messages=0
    local seen_profile=0 seen_target=0 seen_tier=0 seen_rust_filesystem_fsync=0
    rust_filesystem_fsync=not-applicable
    while (( index < ${#input[@]} )); do
        value=${input[index]}
        case ${value} in
        --smoke)
            smoke=1
            output+=("${value}")
            ;;
        --profile|--target|--tier|--rust-filesystem-fsync)
            (( index + 1 < ${#input[@]} )) || return 1
            ((index += 1))
            case ${value} in
            --profile)
                (( seen_profile == 0 )) || return 1
                seen_profile=1
                profile=${input[index]}
                ;;
            --target)
                (( seen_target == 0 )) || return 1
                seen_target=1
                target=${input[index]}
                ;;
            --tier)
                (( seen_tier == 0 )) || return 1
                seen_tier=1
                tier=${input[index]}
                ;;
            --rust-filesystem-fsync)
                (( seen_rust_filesystem_fsync == 0 )) || return 1
                seen_rust_filesystem_fsync=1
                rust_filesystem_fsync=${input[index]}
                ;;
            esac
            [[ ${value} == --rust-filesystem-fsync ]] \
                || output+=("${value}" "${input[index]}")
            ;;
        --profile=*|--target=*|--tier=*|--rust-filesystem-fsync=*)
            case ${value} in
            --profile=*)
                (( seen_profile == 0 )) || return 1
                seen_profile=1
                profile=${value#--profile=}
                ;;
            --target=*)
                (( seen_target == 0 )) || return 1
                seen_target=1
                target=${value#--target=}
                ;;
            --tier=*)
                (( seen_tier == 0 )) || return 1
                seen_tier=1
                tier=${value#--tier=}
                ;;
            --rust-filesystem-fsync=*)
                (( seen_rust_filesystem_fsync == 0 )) || return 1
                seen_rust_filesystem_fsync=1
                rust_filesystem_fsync=${value#--rust-filesystem-fsync=}
                ;;
            esac
            [[ ${value} == --rust-filesystem-fsync=* ]] || output+=("${value}")
            ;;
        --output)
            (( index + 1 < ${#input[@]} )) || return 1
            (( seen_output == 0 )) || return 1
            seen_output=1
            ((index += 1))
            final_output=${input[index]}
            ;;
        --output=*)
            (( seen_output == 0 )) || return 1
            seen_output=1
            final_output=${value#--output=}
            ;;
        --disk-budget-gib)
            (( index + 1 < ${#input[@]} )) || return 1
            ((index += 1))
            ;;
        --disk-budget-gib=*) ;;
        --external-prerequisites|--external-prerequisites-sha256)
            echo "external prerequisite arguments are launcher-owned" >&2
            return 1
            ;;
        --external-prerequisites=*|--external-prerequisites-sha256=*)
            echo "external prerequisite arguments are launcher-owned" >&2
            return 1
            ;;
        --launcher-run-id|--output-fd|--checkpoint-fd)
            echo "artifact capability arguments are launcher-owned" >&2
            return 1
            ;;
        --launcher-run-id=*|--output-fd=*|--checkpoint-fd=*)
            echo "artifact capability arguments are launcher-owned" >&2
            return 1
            ;;
        --profiler-candidate|--profiler-candidate=*)
            echo "profiler candidate selection is launcher-owned" >&2
            return 1
            ;;
        --profiler-messages)
            (( index + 1 < ${#input[@]} )) || return 1
            (( seen_profiler_messages == 0 )) || return 1
            seen_profiler_messages=1
            ((index += 1))
            profiler_messages=${input[index]}
            ;;
        --profiler-messages=*)
            (( seen_profiler_messages == 0 )) || return 1
            seen_profiler_messages=1
            profiler_messages=${value#--profiler-messages=}
            ;;
        *) output+=("${value}") ;;
        esac
        ((index += 1))
    done
    (( seen_output == 1 )) || return 1
    if [[ ${final_output} != /* ]]; then
        final_output=${repository}/${final_output}
    fi
    final_output=$(realpath -m -- "${final_output}")
    local evidence_root
    evidence_root=$(realpath -m -- "${repository}/evidence/performance")
    [[ ${final_output} == "${evidence_root}/"*.json \
        && ${final_output} != *$'\n'* && ${final_output} != *$'\r'* ]]
    [[ ! -e ${final_output} && ! -L ${final_output} ]]
    if [[ ${profile} == java-small ]]; then
        (( seen_profiler_messages == 0 )) || return 1
        [[ ${target} == java && ${smoke} -eq 0 \
            && ${seen_rust_filesystem_fsync} -eq 0 ]] || return 1
        [[ ${tier} == all || ${tier} == 1kb || ${tier} == 10kb ]] || return 1
        java_small_baseline_run=1
        formal_run=0
        disk_budget_gib=20
    elif [[ ${profile} == candidate-stability ]]; then
        (( seen_profiler_messages == 0 )) || return 1
        [[ ${target} == rust ]] || return 1
        if (( smoke != 0 )); then
            if (( seen_rust_filesystem_fsync == 0 )); then
                rust_filesystem_fsync=on
            fi
            formal_run=0
            disk_budget_gib=${LMYZMAIL_BENCHMARK_SMOKE_IMAGE_GIB:-5}
            [[ ${disk_budget_gib} =~ ^[5-9]$|^[1-9][0-9]+$ ]] || return 1
        else
            (( seen_rust_filesystem_fsync == 1 )) || return 1
            formal_run=1
            disk_budget_gib=20
        fi
    elif [[ ${profile} == rust-profiler ]]; then
        [[ ${target} == rust && ${tier} == 10kb && ${smoke} -eq 0 ]] || return 1
        if (( seen_profiler_messages != 0 )); then
            [[ ${profiler_messages} =~ ^[0-9]+$ ]] || return 1
            (( 10#${profiler_messages} >= 64 \
                && 10#${profiler_messages} <= 500000 )) || return 1
        fi
        java_small_baseline_run=0
        profiler_run=1
        formal_run=0
        disk_budget_gib=20
        if (( seen_rust_filesystem_fsync == 0 )); then
            rust_filesystem_fsync=on
        fi
        local normalized
        for index in "${!output[@]}"; do
            normalized=${output[index]}
            if [[ ${normalized} == rust-profiler ]]; then
                output[index]=abba
            elif [[ ${normalized} == --profile=rust-profiler ]]; then
                output[index]=--profile=abba
            fi
        done
        output+=(--profiler-candidate)
        if (( seen_profiler_messages != 0 )); then
            output+=(--profiler-messages "${profiler_messages}")
        fi
    elif [[ ${profile} != abba ]]; then
        return 1
    elif (( smoke != 0 )); then
        (( seen_profiler_messages == 0 )) || return 1
        if [[ ${target} == java ]]; then
            (( seen_rust_filesystem_fsync == 0 )) || return 1
            rust_filesystem_fsync=not-applicable
        elif (( seen_rust_filesystem_fsync == 0 )); then
            rust_filesystem_fsync=on
        fi
        formal_run=0
        disk_budget_gib=${LMYZMAIL_BENCHMARK_SMOKE_IMAGE_GIB:-5}
        [[ ${disk_budget_gib} =~ ^[5-9]$|^[1-9][0-9]+$ ]]
    else
        (( seen_profiler_messages == 0 )) || return 1
        if [[ ${target} == java ]]; then
            (( seen_rust_filesystem_fsync == 0 )) || return 1
            rust_filesystem_fsync=not-applicable
        else
            (( seen_rust_filesystem_fsync == 1 )) || return 1
        fi
        java_small_baseline_run=0
        formal_run=1
        disk_budget_gib=20
    fi
    [[ ${rust_filesystem_fsync} == on \
        || ${rust_filesystem_fsync} == off \
        || ${rust_filesystem_fsync} == not-applicable ]] || return 1
    if [[ ${rust_filesystem_fsync} == on || ${rust_filesystem_fsync} == off ]]; then
        output+=(--rust-filesystem-fsync "${rust_filesystem_fsync}")
    fi
    image_bytes=$((disk_budget_gib * 1024 * 1024 * 1024))
    provisional_output=$(dirname -- "${final_output}")/.$(basename -- "${final_output}").${run_id}.provisional.json
    provisional_checkpoint=${provisional_output}.complete.jsonl
    [[ ! -e ${provisional_output} && ! -L ${provisional_output} \
        && ! -e ${provisional_checkpoint} && ! -L ${provisional_checkpoint} ]]
    runner_arguments=("${output[@]}" --output "${provisional_output}" \
        --launcher-run-id "${run_id}" --output-fd 8 --checkpoint-fd 9 \
        --disk-budget-gib "${disk_budget_gib}")
}

enable_persistent_controllers
recover_incomplete_runs

run_id=$(new_run_id)
derive_run_paths "${run_id}"
declare -a runner_arguments=()
if ! parse_runner_arguments "$@"; then
    echo "invalid SMTP endpoint benchmark launcher arguments" >&2
    exit 2
fi
if ! verify_launcher_isolation_policy; then
    echo "formal SMTP benchmark isolation policy was overridden" >&2
    exit 2
fi
# This check is intentionally before the watchdog, intent journal, image, loop,
# mount, or per-run cgroup mutation.
preflight_image_capacity

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap '' PIPE

# The watchdog knows every resource path from run_id before any current-run
# mutation and inherits the global flock. It is ready before the intent journal.
coproc BENCHMARK_WATCHDOG { root_cleanup_watchdog "$$" "${run_id}"; }
watchdog_pid=${BENCHMARK_WATCHDOG_PID}
watchdog_status_fd=${BENCHMARK_WATCHDOG[0]}
watchdog_control_fd=${BENCHMARK_WATCHDOG[1]}
watchdog_started=1
watchdog_ready= watchdog_reported_pid= watchdog_reported_run=
if ! IFS=' ' read -r -t 5 -u "${watchdog_status_fd}" \
    watchdog_ready watchdog_reported_pid watchdog_reported_run \
    || [[ ${watchdog_ready} != READY \
        || ${watchdog_reported_pid} != "${watchdog_pid}" \
        || ${watchdog_reported_run} != "${run_id}" ]]; then
    echo "benchmark cleanup watchdog did not become ready" >&2
    exit 2
fi

write_intent
stage_checkpoint intent-durable
create_root_artifacts
artifact_output_device=$(stat -c '%d' -- "${output_artifact}")
artifact_output_inode=$(stat -c '%i' -- "${output_artifact}")
artifact_checkpoint_device=$(stat -c '%d' -- "${checkpoint_artifact}")
artifact_checkpoint_inode=$(stat -c '%i' -- "${checkpoint_artifact}")
printf 'ARTIFACTS %s %s %s %s\n' \
    "${artifact_output_device}" "${artifact_output_inode}" \
    "${artifact_checkpoint_device}" "${artifact_checkpoint_inode}" \
    >&"${watchdog_control_fd}"
artifact_tag= artifact_registered_output_device= artifact_registered_output_inode=
artifact_registered_checkpoint_device= artifact_registered_checkpoint_inode=
if ! IFS=' ' read -r -t 5 -u "${watchdog_status_fd}" \
    artifact_tag artifact_registered_output_device artifact_registered_output_inode \
    artifact_registered_checkpoint_device artifact_registered_checkpoint_inode \
    || [[ ${artifact_tag} != ARTIFACTS-REGISTERED \
        || ${artifact_registered_output_device} != "${artifact_output_device}" \
        || ${artifact_registered_output_inode} != "${artifact_output_inode}" \
        || ${artifact_registered_checkpoint_device} != "${artifact_checkpoint_device}" \
        || ${artifact_registered_checkpoint_inode} != "${artifact_checkpoint_inode}" ]]; then
    echo "benchmark watchdog did not anchor artifact capabilities" >&2
    exit 2
fi
stage_checkpoint artifact-capabilities-durable
stage_checkpoint controllers-enabled
allocate_quota_filesystem
configure_run_cgroups

if (( formal_run != 0 )); then
    if ! generate_proxy_attestation || ! create_external_attestation; then
        echo "formal benchmark requires a passing root-owned proxy attestation" >&2
        exit 2
    fi
    runner_arguments+=(
        --external-prerequisites "${external_attestation_path}"
        --external-prerequisites-sha256 "${external_attestation_sha256}"
    )
fi
stage_checkpoint attestation-durable

printf '%s\n' "$$" >"${harness_group}/cgroup.procs"
runner_parent_pid=$$
mkfifo -m 0600 -- "${runner_gate}"
(
    exec {watchdog_control_fd}>&-
    exec {benchmark_lock_fd}>&-
    exec unshare --mount --propagation private \
        bash -ceu '
gate=$1
cgroup_root=$2
shift 2
IFS= read -r gate_value <"${gate}"
[[ ${gate_value} == GO ]]
mount --bind "${cgroup_root}" "${cgroup_root}"
mount -o remount,bind,ro "${cgroup_root}"
exec "$@"
' bash "${runner_gate}" "${cgroup_root}" \
        prlimit --nofile="${nofile_limit}:${nofile_limit}" -- \
        setpriv \
        --reuid "+${benchmark_uid}" \
        --regid "+${benchmark_gid}" \
        --init-groups \
        --pdeathsig SIGINT \
        env -i \
            HOME="${benchmark_home}" \
            SHELL="${benchmark_shell}" \
            USER="${benchmark_login}" \
            LOGNAME="${benchmark_login}" \
            PATH=/usr/bin:/bin \
            LANG=C.UTF-8 \
            LC_ALL=C.UTF-8 \
            TMPDIR="${quota_mount}" \
            LMYZMAIL_BENCHMARK_CGROUP_PARENT="${benchmark_group}" \
            LMYZMAIL_BENCHMARK_HARNESS_CGROUP="${harness_group}" \
            LMYZMAIL_BENCHMARK_WORKLOAD_CGROUP="${workload_group}" \
            LMYZMAIL_BENCHMARK_SERVICES_CGROUP="${services_group}" \
            LMYZMAIL_BENCHMARK_CPU="${benchmark_cpu}" \
            LMYZMAIL_BENCHMARK_HOUSEKEEPING_CPUS="${housekeeping_cpus}" \
            LMYZMAIL_BENCHMARK_DEVICE="${loop_device_id}" \
            LMYZMAIL_BENCHMARK_BACKING_DEVICE="${backing_device_id}" \
            LMYZMAIL_BENCHMARK_IO_BPS="${io_bytes_per_second}" \
            LMYZMAIL_BENCHMARK_MAX_PIDS="${max_pids}" \
            LMYZMAIL_BENCHMARK_MEMORY_HIGH_BYTES="${memory_high_bytes}" \
            LMYZMAIL_BENCHMARK_MAX_MEMORY_BYTES="${max_memory_bytes}" \
            LMYZMAIL_BENCHMARK_NOFILE_LIMIT="${nofile_limit}" \
            LMYZMAIL_BENCHMARK_HOST_RESERVE_BYTES="${host_reserve_bytes}" \
            LMYZMAIL_COORDINATOR_DIAGNOSTIC_STAGES="${LMYZMAIL_COORDINATOR_DIAGNOSTIC_STAGES:-}" \
            LMYZMAIL_BENCHMARK_CGROUP_SUPERVISOR_SOCKET="${migration_socket}" \
            LMYZMAIL_BENCHMARK_LAUNCHER_PID="${runner_parent_pid}" \
            "${venv_python}" -c '
import os
import signal
import sys

expected_parent = int(os.environ.pop("LMYZMAIL_BENCHMARK_LAUNCHER_PID"))
signal.signal(signal.SIGINT, signal.default_int_handler)
if os.getppid() != expected_parent:
    os._exit(125)
os.setsid()
if os.getppid() != expected_parent:
    os._exit(125)
os.execv(sys.argv[1], sys.argv[1:])
' "${venv_python}" "${runner}" "${runner_arguments[@]}"
) &
runner_pid=$!
close_runner_artifact_fds
runner_start_time=$(process_start_time "${runner_pid}")
printf 'RUNNER %s %s\n' "${runner_pid}" "${runner_start_time}" \
    >&"${watchdog_control_fd}"
runner_registered=1
registered_tag= registered_pid= registered_start_time=
if ! IFS=' ' read -r -t 5 -u "${watchdog_status_fd}" \
    registered_tag registered_pid registered_start_time \
    || [[ ${registered_tag} != REGISTERED \
        || ${registered_pid} != "${runner_pid}" \
        || ${registered_start_time} != "${runner_start_time}" ]]; then
    echo "benchmark cgroup supervisor did not register the runner" >&2
    exit 2
fi
if ! release_registered_runner_gate "${runner_pid}" "${runner_start_time}"; then
    echo "benchmark runner gate handshake failed" >&2
    exit 2
fi
rm -f -- "${runner_gate}"
exec {watchdog_status_fd}<&-
watchdog_status_fd=
stage_checkpoint runner-registered
printf '%s\n' "$$" >"${cgroup_root}/cgroup.procs"

set +e
completed_pid=
wait -n -p completed_pid "${runner_pid}" "${watchdog_pid}"
completed_status=$?
set -e
if [[ ${completed_pid} != "${runner_pid}" ]]; then
    echo "benchmark cleanup watchdog exited before the runner (status ${completed_status})" >&2
    watchdog_failed=1
    watchdog_pid=
    exit 1
fi
runner_finished=1
runner_reaped=1
if (( completed_status == 0 )); then
    write_runner_success \
        "${output_artifact}" "${checkpoint_artifact}" "${provisional_output}" \
        "${runner_pid}" "${runner_start_time}"
    stage_checkpoint runner-success-durable
    request=DONE
else
    request=ABORT
fi
printf '%s %s %s\n' "${request}" "${runner_pid}" "${runner_start_time}" \
    >&"${watchdog_control_fd}"
exec {watchdog_control_fd}>&-
watchdog_control_fd=

if ! wait_for_cleanup_watchdog "${watchdog_pid}"; then
    watchdog_failed=1
    watchdog_pid=
    exit 1
fi
watchdog_pid=
stage_checkpoint cleanup-receipt-durable

if (( completed_status == 0 )); then
    publish_provisional "${run_id}"
    stage_checkpoint final-published
fi
cleanup_finalized=1
exit "${completed_status}"
