fn main() {
    cc::Build::new()
        .file("native/map_query.c")
        .flag_if_supported("-std=c11")
        .warnings(true)
        .compile("lmyzmail_xdp_check_map_query");
    println!("cargo:rustc-link-lib=dylib=bpf");
    println!("cargo:rerun-if-changed=native/map_query.c");
}
