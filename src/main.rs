//! `evtxkit` command-line interface: `dump`, `stats` and `grep`.

mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::main()
}
