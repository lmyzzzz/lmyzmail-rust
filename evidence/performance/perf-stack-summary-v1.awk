#!/usr/bin/awk -f

function flush_sample() {
    if (!in_sample) {
        return
    }
    samples++
    materialize += saw_materialize
    select_subdirectory += saw_select_subdirectory
    getdents64 += saw_getdents64
    ext4_readdir += saw_ext4_readdir
    iterate_dir += saw_iterate_dir
    in_sample = 0
    saw_materialize = 0
    saw_select_subdirectory = 0
    saw_getdents64 = 0
    saw_ext4_readdir = 0
    saw_iterate_dir = 0
}

NF == 0 {
    flush_sample()
    next
}

{
    in_sample = 1
}

/OutboundMessageBuilder::materialize/ {
    saw_materialize = 1
}

/select_subdirectory/ {
    saw_select_subdirectory = 1
}

/getdents64/ {
    saw_getdents64 = 1
}

/ext4_readdir/ {
    saw_ext4_readdir = 1
}

/iterate_dir/ {
    saw_iterate_dir = 1
}

END {
    flush_sample()
    print "samples", samples + 0
    print "materialize_samples", materialize + 0
    print "select_subdirectory_samples", select_subdirectory + 0
    print "getdents64_samples", getdents64 + 0
    print "ext4_readdir_samples", ext4_readdir + 0
    print "iterate_dir_samples", iterate_dir + 0
}
