use std::{
    env,
    fs::OpenOptions,
    io::{BufWriter, Write as _},
    path::PathBuf,
};

use lmyzmail::renderer_bench::{
    Backend, BenchmarkConfig, DEFAULT_SIZES, UnsupportedPolicy, run as run_benchmark,
};

const DEFAULT_CONTRAST: f32 = 1.2;
const DEFAULT_DITHER: u8 = 1;
const DEFAULT_WARMUP: usize = 5;
const DEFAULT_ITERATIONS: usize = 30;

fn main() {
    if let Err(error) = run() {
        eprintln!("renderer-simd-bench: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = Arguments::parse(env::args_os().skip(1))?;
    let report = run_benchmark(&BenchmarkConfig {
        input: arguments.input,
        frame_index: arguments.frame_index,
        backend: arguments.backend,
        sizes: arguments.sizes,
        contrast: arguments.contrast,
        dither: arguments.dither,
        warmup: arguments.warmup,
        iterations: arguments.iterations,
        unsupported: arguments.unsupported,
    })
    .map_err(|error| error.to_string())?;

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&arguments.output)
        .map_err(|error| format!("create {}: {error}", arguments.output.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &report)
        .map_err(|error| format!("serialize report: {error}"))?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|error| format!("write {}: {error}", arguments.output.display()))
}

struct Arguments {
    input: PathBuf,
    frame_index: usize,
    backend: Backend,
    sizes: Vec<usize>,
    contrast: f32,
    dither: u8,
    warmup: usize,
    iterations: usize,
    unsupported: UnsupportedPolicy,
    output: PathBuf,
}

impl Arguments {
    fn parse(arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<Self, String> {
        let mut input =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/skibidi_toilet_episode_1.mp4");
        let mut frame_index = 0;
        let mut backend = None;
        let mut sizes = DEFAULT_SIZES.to_vec();
        let mut contrast = DEFAULT_CONTRAST;
        let mut dither = DEFAULT_DITHER;
        let mut warmup = DEFAULT_WARMUP;
        let mut iterations = DEFAULT_ITERATIONS;
        let mut unsupported = UnsupportedPolicy::Fail;
        let mut output = None;
        let mut arguments = arguments.peekable();

        while let Some(argument) = arguments.next() {
            let argument = argument
                .into_string()
                .map_err(|_| "arguments must be valid UTF-8".to_owned())?;
            if argument == "--help" || argument == "-h" {
                print_usage();
                std::process::exit(0);
            }
            let value = arguments
                .next()
                .ok_or_else(|| format!("missing value for {argument}"))?;
            match argument.as_str() {
                "--input" => input = PathBuf::from(value),
                "--frame-index" => frame_index = parse_number(&value, "frame-index")?,
                "--backend" => backend = Some(parse_backend(&value)?),
                "--sizes" => {
                    let value = value
                        .into_string()
                        .map_err(|_| "sizes must be valid UTF-8".to_owned())?;
                    sizes = parse_sizes(&value)?;
                }
                "--contrast" => contrast = parse_number(&value, "contrast")?,
                "--dither" => dither = parse_number(&value, "dither")?,
                "--warmup" => warmup = parse_number(&value, "warmup")?,
                "--iterations" => iterations = parse_number(&value, "iterations")?,
                "--unsupported" => unsupported = parse_unsupported(&value)?,
                "--output" => output = Some(PathBuf::from(value)),
                _ => return Err(format!("unknown argument: {argument}")),
            }
        }

        Ok(Self {
            input,
            frame_index,
            backend: backend.ok_or_else(|| "--backend is required".to_owned())?,
            sizes,
            contrast,
            dither,
            warmup,
            iterations,
            unsupported,
            output: output.ok_or_else(|| "--output is required".to_owned())?,
        })
    }
}

fn parse_number<T: std::str::FromStr>(value: &std::ffi::OsStr, name: &str) -> Result<T, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{name} must be valid UTF-8"))?
        .parse()
        .map_err(|_| format!("invalid {name}"))
}

fn parse_backend(value: &std::ffi::OsStr) -> Result<Backend, String> {
    match value.to_str() {
        Some("scalar") => Ok(Backend::Scalar),
        Some("avx2+fma" | "avx2") => Ok(Backend::Avx2Fma),
        Some("avx512f" | "avx512") => Ok(Backend::Avx512F),
        _ => Err("backend must be scalar, avx2+fma, or avx512f".to_owned()),
    }
}

fn parse_unsupported(value: &std::ffi::OsStr) -> Result<UnsupportedPolicy, String> {
    match value.to_str() {
        Some("fail") => Ok(UnsupportedPolicy::Fail),
        Some("record") => Ok(UnsupportedPolicy::Record),
        _ => Err("unsupported must be fail or record".to_owned()),
    }
}

fn parse_sizes(value: &str) -> Result<Vec<usize>, String> {
    let mut sizes = value
        .split(',')
        .map(|part| {
            part.parse::<usize>()
                .map_err(|_| format!("invalid size: {part}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if sizes.is_empty() {
        return Err("sizes must not be empty".to_owned());
    }
    sizes.sort_unstable();
    sizes.dedup();
    Ok(sizes)
}

fn print_usage() {
    let default_sizes = DEFAULT_SIZES
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "Usage: renderer-simd-bench --backend BACKEND --output PATH [OPTIONS]\n\
         \n\
         Options:\n\
           --input PATH          MP4 input (default: frozen episode asset)\n\
           --frame-index N       zero-based decoded frame (default: 0)\n\
           --backend NAME        scalar, avx2+fma, or avx512f\n\
           --sizes LIST          comma-separated square edges (default: {default_sizes})\n\
           --contrast FLOAT      RGB contrast (default: {DEFAULT_CONTRAST})\n\
           --dither N            map dither 0, 1, or 2 (default: {DEFAULT_DITHER})\n\
           --warmup N            warmup calls per stage (default: {DEFAULT_WARMUP})\n\
           --iterations N        measured calls per stage (default: {DEFAULT_ITERATIONS})\n\
           --unsupported MODE    fail or record (default: fail)\n\
           --output PATH         create a new JSON report"
    );
}
