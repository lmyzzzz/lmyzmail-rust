use std::{env, path::PathBuf};

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

fn main() {
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
    let litehtml_dir = manifest_dir.join("../../vendor/litehtml");
    let litehtml_src = litehtml_dir.join("src");
    let litehtml_include = litehtml_dir.join("include");
    let cairo_container = litehtml_dir.join("containers/cairo");
    let gumbo_dir = litehtml_src.join("gumbo");
    let gumbo_include = gumbo_dir.join("include");

    println!("cargo:rerun-if-changed={}", native_dir.display());
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

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    for path in &cairo.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    println!("cargo:rustc-link-lib=static=lmyzmail_mail_html");
    println!("cargo:rustc-link-lib=static=lmyzmail_gumbo");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    for library in &cairo.libs {
        println!("cargo:rustc-link-lib=dylib={library}");
    }
}
