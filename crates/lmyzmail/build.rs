use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

const GUMBO_SOURCES: &[&str] = &[
    "attribute.c",
    "char_ref.c",
    "error.c",
    "parser.c",
    "string_buffer.c",
    "string_piece.c",
    "tag.c",
    "tokenizer.c",
    "utf8.c",
    "util.c",
    "vector.c",
];

const LITEHTML_SOURCES: &[&str] = &[
    "codepoint.cpp",
    "css_length.cpp",
    "css_selector.cpp",
    "css_tokenizer.cpp",
    "css_parser.cpp",
    "document.cpp",
    "document_container.cpp",
    "el_anchor.cpp",
    "el_base.cpp",
    "el_before_after.cpp",
    "el_body.cpp",
    "el_break.cpp",
    "el_cdata.cpp",
    "el_comment.cpp",
    "el_div.cpp",
    "element.cpp",
    "el_font.cpp",
    "el_image.cpp",
    "el_link.cpp",
    "el_para.cpp",
    "el_script.cpp",
    "el_space.cpp",
    "el_style.cpp",
    "el_table.cpp",
    "el_td.cpp",
    "el_text.cpp",
    "el_title.cpp",
    "el_tr.cpp",
    "encodings.cpp",
    "html.cpp",
    "html_tag.cpp",
    "html_microsyntaxes.cpp",
    "iterators.cpp",
    "media_query.cpp",
    "style.cpp",
    "stylesheet.cpp",
    "table.cpp",
    "tstring_view.cpp",
    "url.cpp",
    "url_path.cpp",
    "utf8_strings.cpp",
    "web_color.cpp",
    "num_cvt.cpp",
    "strtod.cpp",
    "string_id.cpp",
    "css_properties.cpp",
    "line_box.cpp",
    "css_borders.cpp",
    "render_item.cpp",
    "render_block_context.cpp",
    "render_block.cpp",
    "render_inline_context.cpp",
    "render_table.cpp",
    "render_flex.cpp",
    "render_image.cpp",
    "formatting_context.cpp",
    "flex_item.cpp",
    "flex_line.cpp",
    "background.cpp",
    "gradient.cpp",
];

const FFMPEG_NORMALIZATION_VERSION: &str = "lf-text-v2";
const FFMPEG_BUILD_VERSION: &str = "n7.1-minimal-static-v2-reproducible-paths-lf-text-v2";
const XDP_CLANG_VERSION: &str = "18.1.3";
const XDP_FROZEN_SOURCES: &[(&str, &str)] = &[
    (
        "vmlinux.h",
        "4f6a6a70c6542e4692ecfaba15c981c41954fd776f9a21606c3c128234882fd4",
    ),
    (
        "xdp_firewall.bpf.c",
        "7d0d684a65306b44b9b9b1280329e900b9fefd4dabd0018caf40326d34411af5",
    ),
    (
        "xdp_firewall.c",
        "d78c80a1116cab5e0836af7ddb5c51f8b041b19b39a4b0d02922a8d69567b609",
    ),
    (
        "xdp_firewall.h",
        "add5775287fe628e07e30485fac0f54f02a159aa5d2e02b11c0f0c80a5d9935d",
    ),
    (
        "xdp_abi_probe.c",
        "5d2764f5c58467e829c3995593095b522b1b39b82c8785049441863427a0484a",
    ),
];
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo did not set target OS");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo did not set target arch");
    if target_os != "linux" || target_arch != "x86_64" {
        println!(
            "cargo:warning=lmyzmail native mail HTML rendering is built only for Linux x86_64"
        );
        return;
    }

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo did not set CARGO_MANIFEST_DIR"),
    );
    let native_dir = manifest_dir.join("native");
    let xdp_source = manifest_dir.join("../../native/lmyzmail-xdp");
    let ffmpeg_source = manifest_dir.join("../../vendor/ffmpeg-n7.1");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let (ffmpeg_include, ffmpeg_lib) = build_ffmpeg(&ffmpeg_source, &out_dir);
    build_xdp(&xdp_source, &native_dir, &out_dir);
    let litehtml_dir = manifest_dir.join("../../vendor/litehtml");
    let litehtml_src = litehtml_dir.join("src");
    let litehtml_include = litehtml_dir.join("include");
    let cairo_container = litehtml_dir.join("containers/cairo");
    let gumbo_dir = litehtml_src.join("gumbo");
    let gumbo_include = gumbo_dir.join("include");

    println!("cargo:rerun-if-changed={}", native_dir.display());
    println!("cargo:rerun-if-changed={}", xdp_source.display());
    println!("cargo:rerun-if-changed={}", ffmpeg_source.display());
    println!("cargo:rerun-if-changed={}", litehtml_src.display());
    println!("cargo:rerun-if-changed={}", litehtml_include.display());
    println!("cargo:rerun-if-changed={}", cairo_container.display());
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR");

    let cairo = pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("cairo-ft")
        .expect("cairo-ft development files are required to build lmyzmail");

    let mut gumbo = cc::Build::new();
    gumbo
        .cargo_metadata(false)
        .include(&gumbo_include)
        .include(gumbo_include.join("gumbo"))
        .flag_if_supported("-std=c99")
        .warnings(true);
    for source in GUMBO_SOURCES {
        gumbo.file(gumbo_dir.join(source));
    }
    gumbo.compile("lmyzmail_gumbo");

    cc::Build::new()
        .include(&ffmpeg_include)
        .include(&native_dir)
        .file(native_dir.join("ffmpeg_video.c"))
        .flag_if_supported("-std=c11")
        .warnings(true)
        .compile("lmyzmail_ffmpeg_video");

    let mut native = cc::Build::new();
    native
        .cpp(true)
        .cargo_metadata(false)
        .std("c++17")
        .warnings(true)
        .flag_if_supported("-Wpedantic")
        .include(&native_dir)
        .include(&litehtml_src)
        .include(&litehtml_include)
        .include(litehtml_include.join("litehtml"))
        .include(&gumbo_include)
        .include(gumbo_include.join("gumbo"))
        .include(&cairo_container);
    for include in &cairo.include_paths {
        native.include(include);
    }
    for (name, value) in &cairo.defines {
        native.define(name, value.as_deref());
    }
    for source in LITEHTML_SOURCES {
        native.file(litehtml_src.join(source));
    }
    native
        .file(cairo_container.join("container_cairo.cpp"))
        .file(cairo_container.join("cairo_borders.cpp"))
        .file(cairo_container.join("conic_gradient.cpp"))
        .file(native_dir.join("mail_html.cpp"))
        .compile("lmyzmail_mail_html");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    for path in &cairo.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    println!("cargo:rustc-link-lib=static=lmyzmail_mail_html");
    println!("cargo:rustc-link-lib=static=lmyzmail_gumbo");
    println!("cargo:rustc-link-lib=static=lmyzmail_xdp");
    println!("cargo:rustc-link-arg=-Wl,--wrap=bpf_xdp_attach");
    println!("cargo:rustc-link-arg=-Wl,--wrap=bpf_xdp_detach");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    for library in &cairo.libs {
        println!("cargo:rustc-link-lib=dylib={library}");
    }
    println!("cargo:rustc-link-arg=-Wl,--start-group");
    for library in ["avformat", "avcodec", "swscale", "swresample", "avutil"] {
        println!(
            "cargo:rustc-link-arg={}",
            ffmpeg_lib.join(format!("lib{library}.a")).display()
        );
    }
    println!("cargo:rustc-link-arg=-Wl,--end-group");
    for library in ["bpf", "elf", "cap", "z", "m", "dl", "pthread"] {
        println!("cargo:rustc-link-lib=dylib={library}");
    }
}

fn build_xdp(source: &Path, native_dir: &Path, out_dir: &Path) {
    verify_xdp_sources(source);
    let bpf_object = out_dir.join("xdp_firewall.bpf.o");
    let clang = env::var_os("LMYZMAIL_BPF_CLANG").unwrap_or_else(|| "clang".into());
    verify_tool_version(&clang, XDP_CLANG_VERSION);
    run(
        Command::new(clang)
            .current_dir(source)
            .args([
                "-target",
                "bpf",
                "-D__TARGET_ARCH_x86",
                "-O2",
                "-g",
                "-fno-stack-protector",
                "-fdebug-prefix-map=.=native/lmyzmail-xdp",
                "-I",
            ])
            .arg(source)
            .args(["-c", "xdp_firewall.bpf.c", "-o"])
            .arg(&bpf_object),
        "build frozen XDP BPF object",
    );

    let mut native = cc::Build::new();
    native
        .cargo_metadata(false)
        .include(source)
        .file(source.join("xdp_firewall.c"))
        .file(native_dir.join("xdp_attach_guard.c"))
        .flag_if_supported("-std=c11")
        .flag_if_supported("-fPIC")
        .warnings(true);
    if env::var_os("CARGO_FEATURE_XDP_TEST_HOOKS").is_some() {
        native.define("LMYZMAIL_XDP_TEST_HOOKS", "1");
    }
    native.compile("lmyzmail_xdp");

    cc::Build::new()
        .cargo_metadata(false)
        .include(source)
        .file(source.join("xdp_abi_probe.c"))
        .flag_if_supported("-std=c11")
        .warnings(true)
        .compile("lmyzmail_xdp_abi_probe");
}

fn verify_xdp_sources(source: &Path) {
    verify_frozen_sources("XDP", source, XDP_FROZEN_SOURCES);
}

fn verify_frozen_sources(label: &str, source: &Path, expected_sources: &[(&str, &str)]) {
    for (name, expected) in expected_sources {
        let path = source.join(name);
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read frozen {label} source {}: {error}",
                path.display()
            )
        });
        let actual = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual,
            *expected,
            "frozen {label} source hash mismatch for {}",
            path.display()
        );
    }
}

fn verify_tool_version(program: &std::ffi::OsStr, expected: &str) {
    let output = Command::new(program)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("failed to run BPF clang --version: {error}"));
    assert!(output.status.success(), "BPF clang --version failed");
    let version = String::from_utf8_lossy(&output.stdout);
    assert!(
        version
            .lines()
            .next()
            .is_some_and(|line| line.contains(expected)),
        "BPF clang must be version {expected}; got {version:?}"
    );
}

fn build_ffmpeg(source: &Path, out_dir: &Path) -> (PathBuf, PathBuf) {
    let normalized_source = out_dir.join("ffmpeg-n7.1-source");
    let normalization_marker = normalized_source.join(".lmyzmail-normalization-version");
    let build = out_dir.join("ffmpeg-n7.1-build");
    let build_marker = build.join(".lmyzmail-build-version");
    let install = out_dir.join("ffmpeg-n7.1-install");
    let avformat = install.join("lib/libavformat.a");
    if !avformat.is_file() {
        let normalized_current = fs::read_to_string(&normalization_marker)
            .is_ok_and(|version| version == FFMPEG_NORMALIZATION_VERSION);
        if !normalized_current {
            if normalized_source.exists() {
                fs::remove_dir_all(&normalized_source)
                    .expect("failed to clear stale normalized FFmpeg source directory");
            }
            copy_ffmpeg_source(source, &normalized_source);
            fs::write(&normalization_marker, FFMPEG_NORMALIZATION_VERSION)
                .expect("failed to write FFmpeg normalization marker");
        }
        let configured =
            fs::read_to_string(&build_marker).is_ok_and(|version| version == FFMPEG_BUILD_VERSION);
        if !configured {
            if build.exists() {
                fs::remove_dir_all(&build).expect("failed to clear stale FFmpeg build directory");
            }
            if install.exists() {
                fs::remove_dir_all(&install)
                    .expect("failed to clear stale FFmpeg install directory");
            }
            fs::create_dir_all(&build).expect("failed to create FFmpeg build directory");
            fs::create_dir_all(&install).expect("failed to create FFmpeg install directory");

            run(
                Command::new("bash")
                    .arg(normalized_source.join("configure"))
                    .current_dir(&build)
                    .arg(format!("--prefix={}", install.display()))
                    .args([
                        "--enable-static",
                        "--disable-shared",
                        "--enable-pic",
                        "--disable-programs",
                        "--disable-doc",
                        "--disable-network",
                        "--disable-autodetect",
                        "--disable-everything",
                        "--enable-demuxer=mov,avi,matroska,image2,png_pipe,mjpeg,mp4",
                        "--enable-decoder=h264,mpeg4,mjpeg,png,vp8,vp9,hevc,aac,mp3",
                        "--enable-parser=h264,mpeg4video,hevc,mjpeg,png",
                        "--enable-protocol=file",
                        "--enable-swscale",
                        "--enable-zlib",
                        "--disable-avdevice",
                        "--disable-postproc",
                        "--disable-avfilter",
                        "--disable-encoders",
                        "--disable-muxers",
                        "--disable-bsfs",
                        "--disable-devices",
                        "--disable-filters",
                        "--disable-hwaccels",
                        "--disable-asm",
                    ])
                    .arg(format!(
                        "--extra-cflags=-fPIC -O2 -ffile-prefix-map={}=vendor/ffmpeg-n7.1 -fdebug-prefix-map={}=vendor/ffmpeg-n7.1",
                        normalized_source.display(),
                        normalized_source.display(),
                    )),
                "configure FFmpeg n7.1",
            );
            fs::write(&build_marker, FFMPEG_BUILD_VERSION)
                .expect("failed to write FFmpeg build marker");
        } else {
            fs::create_dir_all(&install).expect("failed to create FFmpeg install directory");
        }
        let jobs = std::thread::available_parallelism()
            .map_or(2, usize::from)
            .clamp(1, 8);
        run(
            Command::new("make")
                .current_dir(&build)
                .arg(format!("-j{jobs}")),
            "build FFmpeg n7.1",
        );
        run(
            Command::new("make").current_dir(&build).arg("install"),
            "install FFmpeg n7.1",
        );
    }
    (install.join("include"), install.join("lib"))
}

fn copy_ffmpeg_source(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("failed to create normalized FFmpeg source directory");
    for entry in fs::read_dir(source).expect("failed to read vendored FFmpeg source") {
        let entry = entry.expect("failed to read vendored FFmpeg source entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_ffmpeg_source(&source_path, &destination_path);
            continue;
        }
        fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
            panic!(
                "failed to copy FFmpeg source {}: {error}",
                source_path.display()
            )
        });
        let bytes = fs::read(&destination_path).expect("failed to read copied FFmpeg source");
        if !bytes.contains(&0) && bytes.windows(2).any(|window| window == b"\r\n") {
            let mut normalized = Vec::with_capacity(bytes.len());
            let mut index = 0;
            while index < bytes.len() {
                if index + 1 < bytes.len() && bytes[index] == b'\r' && bytes[index + 1] == b'\n' {
                    normalized.push(b'\n');
                    index += 2;
                } else {
                    normalized.push(bytes[index]);
                    index += 1;
                }
            }
            fs::write(&destination_path, normalized)
                .expect("failed to normalize copied FFmpeg source");
        }
    }
}

fn run(command: &mut Command, operation: &str) {
    command.env("LC_ALL", "C");
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {operation}: {error}"));
    assert!(status.success(), "failed to {operation}: {status}");
}
