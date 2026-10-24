//! Command implementations.
//!
//! Every subcommand runs the same per-file loop: open the file, decode its
//! chunks in parallel with [`evtxkit::pipeline::run`], and let a sequential
//! sink write output, merge statistics and log errors in file order.

mod args;

use anyhow::{Context, Result, bail};
use args::{Cli, Command, DumpArgs, Format, GrepArgs, InputArgs, StatsArgs};
use clap::Parser;
use evtxkit::binxml::Limits;
use evtxkit::fields::{self, FieldMap};
use evtxkit::filter::FilterSet;
use evtxkit::mapping::{LogSource, Mapping};
use evtxkit::pipeline::{self, CrcPolicy, PipelineConfig, SlotInfo, SlotKind};
use evtxkit::record::RecordError;
use evtxkit::render;
use evtxkit::stats::Stats;
use evtxkit::{CrcStatus, EvtxFile};
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use tracing::{info, warn};

/// Entry point used by `main`.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose, cli.quiet);
    let result = match &cli.command {
        Command::Dump(a) => dump(a),
        Command::Stats(a) => stats(a),
        Command::Grep(a) => grep(a),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("evtxkit: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn init_logging(verbose: u8, quiet: bool) {
    let default = match (quiet, verbose) {
        (true, _) => "error",
        (false, 0) => "warn",
        (false, 1) => "info",
        (false, _) => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .with_target(false)
        .without_time()
        .try_init();
}

/// What to do with each record; shared read-only by all workers.
struct Job {
    mapping: Option<Mapping>,
    filters: FilterSet,
    category: Option<String>,
    service: Option<String>,
    format: Option<Format>,
    emit_errors: bool,
    group_by: Option<String>,
    policy: CrcPolicy,
}

impl Job {
    fn needs_fields(&self) -> bool {
        self.mapping.is_some()
            || !self.filters.is_empty()
            || self.group_by.is_some()
            || self.format == Some(Format::Fields)
    }
}

/// Output of one chunk, produced on a worker thread.
struct ChunkOut {
    info: SlotInfo,
    text: String,
    matched: u64,
    stats: Stats,
    errors: Vec<RecordError>,
}

fn process_slot(job: &Job, slot: evtxkit::ChunkSlot<'_>) -> ChunkOut {
    let batch = pipeline::decode_slot(slot, job.policy, Limits::default());
    let slot_level = batch.info.kind != SlotKind::Chunk || batch.info.skipped;
    let mut out = ChunkOut {
        info: batch.info,
        text: String::new(),
        matched: 0,
        stats: Stats::default(),
        errors: Vec::new(),
    };
    out.stats.add_slot(&out.info);
    for item in batch.records {
        let record = match item {
            Ok(r) => r,
            Err(e) => {
                out.stats.add_error(&e, slot_level);
                if job.emit_errors && matches!(job.format, Some(Format::Jsonl | Format::Fields)) {
                    out.text.push_str(&render::json::error_line(&e));
                    out.text.push('\n');
                }
                out.errors.push(e);
                continue;
            }
        };
        let mut logsource: Option<LogSource> = None;
        let mut field_map = FieldMap::new();
        if job.needs_fields() {
            field_map = fields::flatten(&record);
            if let Some(m) = &job.mapping {
                logsource = Some(m.apply(&mut field_map));
            }
        }
        let group = job
            .group_by
            .as_deref()
            .map(|f| Stats::group_value(&field_map, f));
        out.stats.add_record(&record, group.as_deref());
        if let Some(ls) = &logsource {
            let wanted = |want: &Option<String>, have: &Option<String>| {
                want.as_ref()
                    .is_none_or(|w| have.as_ref().is_some_and(|h| h.eq_ignore_ascii_case(w)))
            };
            if !wanted(&job.category, &ls.category) || !wanted(&job.service, &ls.service) {
                continue;
            }
        }
        if !job.filters.matches(&field_map) {
            continue;
        }
        out.matched += 1;
        match job.format {
            Some(Format::Jsonl) => {
                render::json::write_record(&mut out.text, &record);
                out.text.push('\n');
            }
            Some(Format::Xml) => out.text.push_str(&render::xml::record_document(&record)),
            Some(Format::Fields) => {
                let ls = logsource.as_ref().map(LogSource::to_json);
                out.text
                    .push_str(&fields::record_line(&record, &field_map, ls.as_deref()));
                out.text.push('\n');
            }
            None => {}
        }
    }
    out
}

/// Per-file result handed back to the command.
struct FileResult {
    stats: Stats,
    matched: u64,
    slots: Vec<SlotInfo>,
    /// The output pipe was closed by the reader; stop quietly.
    closed: bool,
}

fn threads(input: &InputArgs) -> usize {
    input
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from))
        .max(1)
}

fn load_mapping(input: &InputArgs, force: bool) -> Result<Option<Mapping>> {
    if let Some(path) = &input.mapping {
        return Mapping::from_path(path)
            .map(Some)
            .with_context(|| format!("loading mapping {}", path.display()));
    }
    Ok((input.sigma || force).then(Mapping::builtin))
}

fn run_file(
    path: &Path,
    input: &InputArgs,
    job: &Job,
    out: &mut dyn Write,
    keep_slots: bool,
) -> Result<FileResult> {
    let file = EvtxFile::open(path).with_context(|| format!("opening {}", path.display()))?;
    let h = file.header();
    if let CrcStatus::Mismatch { stored, computed } = h.crc {
        warn!(
            file = %path.display(),
            "file header CRC32 mismatch (stored {stored:#010x}, computed {computed:#010x})"
        );
    }
    let mut result = FileResult {
        stats: Stats::default(),
        matched: 0,
        slots: Vec::new(),
        closed: false,
    };
    let cfg = PipelineConfig::new(threads(input));
    let outcome = pipeline::run(
        &file,
        cfg,
        |slot| process_slot(job, slot),
        |chunk: ChunkOut| -> io::Result<()> {
            for e in &chunk.errors {
                warn!(file = %path.display(), "{e}");
            }
            if let Some(CrcStatus::Mismatch { .. }) = chunk.info.header_crc {
                warn!(file = %path.display(), chunk = chunk.info.index, "chunk header CRC32 mismatch");
            }
            if let Some(CrcStatus::Mismatch { .. }) = chunk.info.records_crc {
                info!(file = %path.display(), chunk = chunk.info.index, "chunk record-data CRC32 mismatch");
            }
            result.stats.merge(&chunk.stats);
            result.matched += chunk.matched;
            if keep_slots {
                result.slots.push(chunk.info);
            }
            out.write_all(chunk.text.as_bytes())
        },
    );
    match outcome {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => result.closed = true,
        Err(e) => return Err(e).context("writing output"),
    }
    info!(
        file = %path.display(),
        records = result.stats.records,
        errors = result.stats.record_errors,
        matched = result.matched,
        "done"
    );
    Ok(result)
}

fn open_output(path: Option<&Path>) -> Result<Box<dyn Write>> {
    Ok(match path {
        Some(p) => Box::new(BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("creating {}", p.display()))?,
        )),
        None => Box::new(BufWriter::with_capacity(1 << 16, io::stdout().lock())),
    })
}

fn finish(out: &mut dyn Write) -> Result<()> {
    match out.flush() {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e).context("writing output"),
        _ => Ok(()),
    }
}

fn policy(input: &InputArgs) -> CrcPolicy {
    if input.strict_crc {
        CrcPolicy::Skip
    } else {
        CrcPolicy::Report
    }
}

fn dump(a: &DumpArgs) -> Result<ExitCode> {
    let job = Job {
        mapping: load_mapping(&a.input, false)?,
        filters: FilterSet::parse(&a.filters)?,
        category: None,
        service: None,
        format: Some(a.format),
        emit_errors: a.emit_errors,
        group_by: None,
        policy: policy(&a.input),
    };
    let mut out = open_output(a.output.as_deref())?;
    for path in &a.input.files {
        if run_file(path, &a.input, &job, &mut *out, false)?.closed {
            break;
        }
    }
    finish(&mut *out)?;
    Ok(ExitCode::SUCCESS)
}

fn grep(a: &GrepArgs) -> Result<ExitCode> {
    if a.text.is_none() && a.filters.is_empty() && a.category.is_none() && a.service.is_none() {
        bail!("grep needs a pattern: give --text, --where, --category or --service");
    }
    let wants_logsource = a.category.is_some() || a.service.is_some();
    let job = Job {
        mapping: load_mapping(&a.input, wants_logsource)?,
        filters: FilterSet::parse(&a.filters)?.with_text(a.text.as_deref()),
        category: a.category.clone(),
        service: a.service.clone(),
        format: (!a.count).then_some(a.format),
        emit_errors: false,
        group_by: None,
        policy: policy(&a.input),
    };
    let mut out = open_output(None)?;
    let mut matched = 0;
    for path in &a.input.files {
        let r = run_file(path, &a.input, &job, &mut *out, false)?;
        matched += r.matched;
        if r.closed {
            break;
        }
    }
    if a.count {
        let _ = writeln!(out, "{matched}");
    }
    finish(&mut *out)?;
    Ok(if matched > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn crc_label(c: Option<CrcStatus>) -> &'static str {
    match c {
        Some(CrcStatus::Valid) => "ok",
        Some(CrcStatus::Mismatch { .. }) => "MISMATCH",
        Some(CrcStatus::Disabled) => "disabled",
        None => "-",
    }
}

fn slot_json(s: &SlotInfo) -> serde_json::Value {
    serde_json::json!({
        "index": s.index,
        "kind": format!("{:?}", s.kind).to_lowercase(),
        "record_id_range": s.record_id_range,
        "header_crc": crc_label(s.header_crc),
        "records_crc": crc_label(s.records_crc),
        "templates": s.templates,
        "skipped": s.skipped,
    })
}

fn stats(a: &StatsArgs) -> Result<ExitCode> {
    let job = Job {
        mapping: load_mapping(&a.input, false)?,
        filters: FilterSet::default(),
        category: None,
        service: None,
        format: None,
        emit_errors: false,
        group_by: a.by.clone(),
        policy: policy(&a.input),
    };
    let mut total = Stats::default();
    let mut reports = Vec::new();
    let mut text = String::new();
    for path in &a.input.files {
        let file = EvtxFile::open(path).with_context(|| format!("opening {}", path.display()))?;
        let h = file.header().clone();
        drop(file);
        let r = run_file(path, &a.input, &job, &mut io::sink(), a.chunks)?;
        total.merge(&r.stats);
        if a.json {
            let mut v = r.stats.to_json(a.top, a.by.as_deref());
            v["file"] = serde_json::json!(path.display().to_string());
            v["format_version"] =
                serde_json::json!(format!("{}.{}", h.major_version, h.minor_version));
            v["header_crc"] = serde_json::json!(crc_label(Some(h.crc)));
            v["dirty"] = serde_json::json!(h.is_dirty());
            if a.chunks {
                v["chunk_slots"] = r.slots.iter().map(slot_json).collect();
            }
            reports.push(v);
        } else {
            text.push_str(&format!(
                "{}\n  format     {}.{}, header CRC {}, {}\n",
                path.display(),
                h.major_version,
                h.minor_version,
                crc_label(Some(h.crc)),
                if h.is_dirty() { "dirty" } else { "clean" }
            ));
            text.push_str(&r.stats.render_text(a.top, a.by.as_deref()));
            if a.chunks {
                text.push_str(
                    "  slot  kind     record ids              hdr-crc   data-crc  templates\n",
                );
                for s in &r.slots {
                    let ids = s
                        .record_id_range
                        .map_or("-".to_string(), |(f, l)| format!("{f}..{l}"));
                    text.push_str(&format!(
                        "  {:>4}  {:<8} {:<23} {:<9} {:<9} {}\n",
                        s.index,
                        format!("{:?}", s.kind).to_lowercase(),
                        ids,
                        crc_label(s.header_crc),
                        crc_label(s.records_crc),
                        s.templates
                    ));
                }
            }
        }
    }
    let mut out = open_output(None)?;
    if a.json {
        let doc = serde_json::json!({
            "files": reports,
            "total": total.to_json(a.top, a.by.as_deref()),
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)?;
    } else {
        if a.input.files.len() > 1 {
            text.push_str("total\n");
            text.push_str(&total.render_text(a.top, a.by.as_deref()));
        }
        out.write_all(text.as_bytes())?;
    }
    finish(&mut *out)?;
    Ok(ExitCode::SUCCESS)
}
