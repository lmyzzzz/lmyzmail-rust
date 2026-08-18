use std::{
    env,
    fmt::Write as _,
    fs,
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
const SKIBIDI_FROZEN_SOURCES: &[(&str, &str)] = &[
    (
        "skibidi_avx.c",
        "7e8e7f3ee5bea0ac8d0857bd5bc8d806b44e5142c17ec8b5b6583db7c62fc613",
    ),
    (
        "skibidi_avx.h",
        "bde8e9d19d6668c644aba1cdd81fb9f56c2236ff827ddd16fb366369bc68bbea",
    ),
];
const SKIBIDI_EXPORTS: &[&str] = &[
    "skibidi_init",
    "skibidi_configure",
    "skibidi_get_config",
    "skibidi_generate",
    "skibidi_generate_variant",
    "skibidi_generate_batch",
    "skibidi_destroy",
    "skibidi_alloc_context",
    "skibidi_alloc_context_array",
    "skibidi_free_context",
    "skibidi_version",
    "skibidi_has_avx2",
    "skibidi_has_avx512",
    "skibidi_get_capabilities",
    "skibidi_get_active_simd",
    "skibidi_is_avx512_enabled",
    "skibidi_get_rng_state_size",
    "skibidi_get_context_size",
    "skibidi_get_context_alignment",
];
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
    let skibidi_source = manifest_dir.join("../../native/lmyzmail-skibidi/upstream");
    let xdp_source = manifest_dir.join("../../native/lmyzmail-xdp");
    let ffmpeg_source = manifest_dir.join("../../vendor/ffmpeg-n7.1");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    build_skibidi(&skibidi_source, &out_dir);
    let (ffmpeg_include, ffmpeg_lib) = build_ffmpeg(&ffmpeg_source, &out_dir);
    build_xdp(&xdp_source, &native_dir, &out_dir);
    let litehtml_dir = manifest_dir.join("../../vendor/litehtml");
    let litehtml_src = litehtml_dir.join("src");
    let litehtml_include = litehtml_dir.join("include");
    let cairo_container = litehtml_dir.join("containers/cairo");
    let gumbo_dir = litehtml_src.join("gumbo");
    let gumbo_include = gumbo_dir.join("include");

    println!("cargo:rerun-if-changed={}", native_dir.display());
    println!("cargo:rerun-if-changed={}", skibidi_source.display());
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

struct SkibidiCompilerIdentity {
    path: PathBuf,
    family: &'static str,
    version: &'static str,
    version_line: String,
}

struct SkibidiVariantBuild {
    name: String,
    library: String,
    effective_compiler_args: Vec<String>,
}

fn build_skibidi(source: &Path, out_dir: &Path) {
    verify_frozen_sources("Skibidi 1.8.0", source, SKIBIDI_FROZEN_SOURCES);
    reject_skibidi_cflags();
    let compiler = resolve_skibidi_compiler();

    let scalar = build_skibidi_variant(
        source,
        &compiler,
        "scalar",
        "lmyzmail_skibidi_scalar",
        &[
            "-march=x86-64",
            "-mno-avx",
            "-mno-avx2",
            "-mno-avx512f",
            "-mno-avx512vl",
            "-mno-avx512bw",
            "-mno-avx512dq",
            "-mno-fma",
        ],
    );
    let avx2 = build_skibidi_variant(
        source,
        &compiler,
        "avx2",
        "lmyzmail_skibidi_avx2",
        &[
            "-march=x86-64",
            "-mavx2",
            "-mno-avx512f",
            "-mno-avx512vl",
            "-mno-avx512bw",
            "-mno-avx512dq",
            "-mno-fma",
        ],
    );
    let avx512 = build_skibidi_variant(
        source,
        &compiler,
        "avx512",
        "lmyzmail_skibidi_avx512",
        &[
            "-march=x86-64",
            "-mavx2",
            "-mavx512f",
            "-mavx512vl",
            "-mavx512bw",
            "-mavx512dq",
            "-mno-fma",
        ],
    );
    write_skibidi_build_manifest(out_dir, &compiler, &[scalar, avx2, avx512]);
}

fn build_skibidi_variant(
    source: &Path,
    compiler: &SkibidiCompilerIdentity,
    variant: &str,
    library: &str,
    flags: &[&str],
) -> SkibidiVariantBuild {
    let mut native = cc::Build::new();
    native
        .compiler(&compiler.path)
        .cargo_metadata(false)
        .no_default_flags(true)
        .inherit_rustflags(false)
        .include(source)
        .file(source.join("skibidi_avx.c"))
        .flag("--target=x86_64-unknown-linux-gnu")
        .flag("-O3")
        .flag("-std=c11")
        .flag("-fPIC")
        .flag("-fno-lto")
        .flag("-Werror")
        .warnings(true)
        .extra_warnings(true)
        .flag("-Wpedantic");
    for flag in flags {
        native.flag(flag);
    }
    for symbol in SKIBIDI_EXPORTS {
        let stem = symbol
            .strip_prefix("skibidi_")
            .expect("Skibidi export must have the skibidi_ prefix");
        let renamed = format!("lmyzmail_skibidi_{variant}_{stem}");
        native.define(symbol, Some(renamed.as_str()));
    }

    let tool = native.get_compiler();
    if !tool.is_like_clang() || tool.is_like_clang_cl() {
        panic!(
            "frozen Skibidi variants require clang family; cc identified {:?}",
            tool.path()
        );
    }
    let command = tool.to_command();
    let actual_program = fs::canonicalize(command.get_program()).unwrap_or_else(|error| {
        panic!(
            "failed to canonicalize effective Skibidi compiler {:?}: {error}",
            command.get_program()
        )
    });
    assert_eq!(
        actual_program, compiler.path,
        "cc selected a compiler wrapper or a different compiler for frozen Skibidi"
    );
    let effective_compiler_args = command
        .get_args()
        .map(|argument| {
            argument
                .to_str()
                .unwrap_or_else(|| panic!("Skibidi compiler argument is not UTF-8: {:?}", argument))
                .to_owned()
        })
        .collect::<Vec<_>>();
    validate_skibidi_compiler_args(variant, &effective_compiler_args);
    native.compile(library);
    SkibidiVariantBuild {
        name: variant.to_owned(),
        library: library.to_owned(),
        effective_compiler_args,
    }
}

fn reject_skibidi_cflags() {
    let target = env::var("TARGET").expect("Cargo did not set TARGET");
    let host = env::var("HOST").expect("Cargo did not set HOST");
    let normalized_target = target.replace(['-', '.'], "_");
    let kind = if target == host { "HOST" } else { "TARGET" };
    let names = [
        "CFLAGS".to_owned(),
        format!("{kind}_CFLAGS"),
        "CFLAGS_x86_64".to_owned(),
        format!("CFLAGS_{target}"),
        format!("CFLAGS_{normalized_target}"),
    ];
    for name in names {
        println!("cargo:rerun-if-env-changed={name}");
        if env::var_os(&name).is_some_and(|value| !value.is_empty()) {
            panic!(
                "{name} must be unset when compiling frozen Skibidi variants; \
                 per-variant ISA flags are part of the SIGILL safety contract"
            );
        }
    }
}

fn resolve_skibidi_compiler() -> SkibidiCompilerIdentity {
    println!("cargo:rerun-if-env-changed=LMYZMAIL_SKIBIDI_CC");
    println!("cargo:rerun-if-env-changed=LMYZMAIL_BPF_CLANG");
    println!("cargo:rerun-if-env-changed=PATH");
    let configured = env::var_os("LMYZMAIL_SKIBIDI_CC")
        .or_else(|| env::var_os("LMYZMAIL_BPF_CLANG"))
        .unwrap_or_else(|| "clang".into());
    let path = resolve_program(&configured).unwrap_or_else(|| {
        panic!(
            "Skibidi compiler {:?} was not found as one executable path; embedded compiler arguments are forbidden",
            configured
        )
    });
    let path = fs::canonicalize(&path).unwrap_or_else(|error| {
        panic!(
            "failed to canonicalize Skibidi compiler {}: {error}",
            path.display()
        )
    });
    assert!(
        path.is_file(),
        "Skibidi compiler is not a file: {}",
        path.display()
    );

    let output = Command::new(&path)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "failed to run Skibidi compiler {} --version: {error}",
                path.display()
            )
        });
    assert!(
        output.status.success(),
        "Skibidi compiler {} --version failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)
        .expect("Skibidi compiler --version stdout must be valid UTF-8");
    let version_line = stdout
        .lines()
        .next()
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| {
            panic!(
                "Skibidi compiler {} --version returned no first line",
                path.display()
            )
        })
        .to_owned();
    let marker = "clang version ";
    let marker_start = version_line
        .to_ascii_lowercase()
        .find(marker)
        .unwrap_or_else(|| panic!("Skibidi compiler must identify as clang; got {version_line:?}"));
    let version = version_line[marker_start + marker.len()..]
        .split_ascii_whitespace()
        .next()
        .expect("clang --version line must contain a version");
    assert_eq!(
        version, XDP_CLANG_VERSION,
        "Skibidi compiler must be clang {}; got {version_line:?}",
        XDP_CLANG_VERSION
    );
    SkibidiCompilerIdentity {
        path,
        family: "clang",
        version: XDP_CLANG_VERSION,
        version_line,
    }
}

fn resolve_program(program: &std::ffi::OsStr) -> Option<PathBuf> {
    let configured = PathBuf::from(program);
    if configured.is_absolute() || configured.components().count() > 1 {
        return configured.is_file().then_some(configured);
    }
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(&configured))
            .find(|candidate| candidate.is_file())
    })
}

fn validate_skibidi_compiler_args(variant: &str, args: &[String]) {
    let march = args
        .iter()
        .filter(|argument| argument.starts_with("-march"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        march,
        ["-march=x86-64"],
        "unexpected -march flags for Skibidi {variant}: {march:?}"
    );

    let actual_avx = args
        .iter()
        .filter(|argument| argument.starts_with("-mavx"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    let expected_avx: &[&str] = match variant {
        "scalar" => &[],
        "avx2" => &["-mavx2"],
        "avx512" => &[
            "-mavx2",
            "-mavx512f",
            "-mavx512vl",
            "-mavx512bw",
            "-mavx512dq",
        ],
        _ => panic!("unknown Skibidi variant {variant:?}"),
    };
    assert_eq!(
        actual_avx, expected_avx,
        "unexpected -mavx flags for Skibidi {variant}: {actual_avx:?}"
    );
    let target = args
        .iter()
        .filter(|argument| argument.starts_with("--target") || argument.starts_with("-target"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        target,
        ["--target=x86_64-unknown-linux-gnu"],
        "unexpected target flags for Skibidi {variant}: {target:?}"
    );
    assert!(
        args.iter().any(|argument| argument == "-fno-lto"),
        "Skibidi {variant} is missing -fno-lto"
    );
    assert!(
        !args.iter().any(|argument| {
            argument.starts_with("-flto")
                || argument == "-fuse-linker-plugin"
                || argument.contains("target-feature")
        }),
        "unexpected LTO or target-feature argument for Skibidi {variant}: {args:?}"
    );
}

fn write_skibidi_build_manifest(
    out_dir: &Path,
    compiler: &SkibidiCompilerIdentity,
    variants: &[SkibidiVariantBuild],
) {
    let mut manifest = String::new();
    writeln!(&mut manifest, "{{").unwrap();
    writeln!(&mut manifest, "  \"schema_version\": 1,").unwrap();
    writeln!(
        &mut manifest,
        "  \"target\": {},",
        json_string("x86_64-unknown-linux-gnu")
    )
    .unwrap();
    writeln!(&mut manifest, "  \"compiler\": {{").unwrap();
    writeln!(
        &mut manifest,
        "    \"path\": {},",
        json_string(&compiler.path.to_string_lossy())
    )
    .unwrap();
    writeln!(
        &mut manifest,
        "    \"family\": {},",
        json_string(compiler.family)
    )
    .unwrap();
    writeln!(
        &mut manifest,
        "    \"version\": {},",
        json_string(compiler.version)
    )
    .unwrap();
    writeln!(
        &mut manifest,
        "    \"version_line\": {}",
        json_string(&compiler.version_line)
    )
    .unwrap();
    writeln!(&mut manifest, "  }},").unwrap();
    writeln!(&mut manifest, "  \"variants\": [").unwrap();
    for (index, variant) in variants.iter().enumerate() {
        writeln!(&mut manifest, "    {{").unwrap();
        writeln!(
            &mut manifest,
            "      \"name\": {},",
            json_string(&variant.name)
        )
        .unwrap();
        writeln!(
            &mut manifest,
            "      \"library\": {},",
            json_string(&variant.library)
        )
        .unwrap();
        writeln!(&mut manifest, "      \"effective_compiler_args\": [").unwrap();
        for (argument_index, argument) in variant.effective_compiler_args.iter().enumerate() {
            let comma = if argument_index + 1 == variant.effective_compiler_args.len() {
                ""
            } else {
                ","
            };
            writeln!(&mut manifest, "        {}{comma}", json_string(argument)).unwrap();
        }
        writeln!(&mut manifest, "      ]").unwrap();
        let comma = if index + 1 == variants.len() { "" } else { "," };
        writeln!(&mut manifest, "    }}{comma}").unwrap();
    }
    writeln!(&mut manifest, "  ]").unwrap();
    writeln!(&mut manifest, "}}").unwrap();

    let path = out_dir.join("lmyzmail-skibidi-build-manifest.json");
    let temporary = out_dir.join(format!(
        ".lmyzmail-skibidi-build-manifest.{}.tmp",
        std::process::id()
    ));
    fs::write(&temporary, manifest).unwrap_or_else(|error| {
        panic!(
            "failed to write Skibidi build manifest {}: {error}",
            temporary.display()
        )
    });
    fs::rename(&temporary, &path).unwrap_or_else(|error| {
        panic!(
            "failed to publish Skibidi build manifest {}: {error}",
            path.display()
        )
    });
}

fn json_string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            character if character <= '\u{001f}' => {
                write!(&mut encoded, "\\u{:04x}", character as u32).unwrap();
            }
            character => encoded.push(character),
        }
    }
    encoded.push('"');
    encoded
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
