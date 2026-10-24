//! Command-line argument definitions.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// From-scratch Windows EVTX parser: JSONL/XML output, statistics and field search.
#[derive(Debug, Parser)]
#[command(name = "evtxkit", version, about, long_about = None)]
pub struct Cli {
    /// More logging on stderr (-v info, -vv debug). RUST_LOG overrides.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
    /// Only log errors.
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// Subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Decode records to JSON Lines (default), XML or flat field objects.
    Dump(DumpArgs),
    /// Summarise files: chunk/CRC health, record counts, top event IDs and providers.
    Stats(StatsArgs),
    /// Print records matching a text pattern and/or field filters.
    Grep(GrepArgs),
}

/// Output formats for `dump` and `grep`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// One JSON object per record (element tree mapping).
    Jsonl,
    /// One XML document per record.
    Xml,
    /// One flat field object per record (with `_logsource` when mapping).
    Fields,
}

/// Options shared by every subcommand.
#[derive(Debug, Args)]
pub struct InputArgs {
    /// EVTX files to read.
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
    /// Worker threads for chunk-parallel decoding (default: all cores).
    #[arg(short = 't', long)]
    pub threads: Option<usize>,
    /// Skip chunks whose CRC32 checksums do not verify (default: report and decode).
    #[arg(long)]
    pub strict_crc: bool,
    /// Apply the built-in Sigma Windows field mapping.
    #[arg(long)]
    pub sigma: bool,
    /// Apply a custom field-mapping YAML file (see mappings/sigma-windows.yml).
    #[arg(long, value_name = "FILE", conflicts_with = "sigma")]
    pub mapping: Option<PathBuf>,
}

/// `dump` options.
#[derive(Debug, Args)]
pub struct DumpArgs {
    /// Shared input options.
    #[command(flatten)]
    pub input: InputArgs,
    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Jsonl)]
    pub format: Format,
    /// Field filter, e.g. `EventID=4624` or `Image|endswith=\cmd.exe` (repeatable, ANDed).
    #[arg(short = 'w', long = "where", value_name = "EXPR")]
    pub filters: Vec<String>,
    /// Emit `{"error":true,...}` lines for undecodable records (JSONL formats).
    #[arg(long)]
    pub emit_errors: bool,
    /// Write output to FILE instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// `stats` options.
#[derive(Debug, Args)]
pub struct StatsArgs {
    /// Shared input options.
    #[command(flatten)]
    pub input: InputArgs,
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
    /// Also count records per value of this (mapped) field.
    #[arg(long, value_name = "FIELD")]
    pub by: Option<String>,
    /// Number of entries in each top-N list.
    #[arg(long, default_value_t = 5)]
    pub top: usize,
    /// List every chunk slot with its CRC status.
    #[arg(long)]
    pub chunks: bool,
}

/// `grep` options.
#[derive(Debug, Args)]
pub struct GrepArgs {
    /// Shared input options.
    #[command(flatten)]
    pub input: InputArgs,
    /// Case-insensitive text that must appear in some field value.
    #[arg(short = 'e', long = "text", value_name = "TEXT")]
    pub text: Option<String>,
    /// Field filter (repeatable, ANDed); see `dump --where`.
    #[arg(short = 'w', long = "where", value_name = "EXPR")]
    pub filters: Vec<String>,
    /// Only records tagged with this Sigma category (implies --sigma).
    #[arg(long)]
    pub category: Option<String>,
    /// Only records from this Sigma service (implies --sigma).
    #[arg(long)]
    pub service: Option<String>,
    /// Print only the number of matching records.
    #[arg(short, long)]
    pub count: bool,
    /// Output format for matches.
    #[arg(short, long, value_enum, default_value_t = Format::Jsonl)]
    pub format: Format,
}
