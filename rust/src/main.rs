mod checks;
mod config;
mod diff;
mod models;
mod output;
mod scanner;
mod tokenizer;
mod unicode_data;

use std::io::IsTerminal;
use std::{env, fs, path::Path, process};

use anyhow::Result;
use clap::Parser;

use config::load_policy;
use diff::get_changed_lines;
use models::Severity;
use output::{
    emit_annotations, format_finding, format_summary, write_github_outputs, write_sarif,
    write_step_summary,
};
use scanner::{collect_files, scan_file, should_exclude};

#[derive(Parser)]
#[command(
    name = "unicode-safety-check",
    about = "Detect adversarial Unicode in source files"
)]
struct Cli {
    files: Vec<String>,
    #[arg(long, conflicts_with = "all")]
    file_list: Option<String>,
    #[arg(long, conflicts_with = "file_list")]
    all: bool,
    #[arg(long)]
    policy: Option<String>,
    #[arg(long)]
    base_sha: Option<String>,
    #[arg(long)]
    sarif_file: Option<String>,
    #[arg(long)]
    no_annotations: bool,
    #[arg(long)]
    fail_on_warn: bool,
    #[arg(long, action = clap::ArgAction::Append)]
    exclude: Vec<String>,
    #[arg(long)]
    no_color: bool,
}

fn main() -> Result<()> {
    let mut args = Cli::parse();

    // Override from environment variables
    let policy_path = args
        .policy
        .take()
        .or_else(|| env::var("INPUT_POLICY_FILE").ok().filter(|s| !s.is_empty()));

    if env::var("INPUT_FAIL_ON_WARN")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true")
    {
        args.fail_on_warn = true;
    }
    if env::var("INPUT_DISABLE_ANNOTATIONS")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true")
    {
        args.no_annotations = true;
    }

    let sarif_file = args
        .sarif_file
        .take()
        .or_else(|| env::var("INPUT_SARIF_FILE").ok().filter(|s| !s.is_empty()));

    let base_sha = args
        .base_sha
        .take()
        .or_else(|| env::var("INPUT_BASE_SHA").ok().filter(|s| !s.is_empty()));

    let scan_all = args.all || env::var("INPUT_SCAN_MODE").ok().as_deref() == Some("all");

    let mut excludes = args.exclude.clone();
    if let Ok(env_exc) = env::var("INPUT_EXCLUDE_PATTERNS") {
        for line in env_exc.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                excludes.push(trimmed.to_string());
            }
        }
    }

    // Load policy
    let policy = load_policy(policy_path.as_deref())?;

    // Collect files
    let files = if scan_all {
        collect_files(".")
    } else if let Some(ref list_path) = args.file_list {
        let content = fs::read_to_string(list_path)
            .map_err(|e| anyhow::anyhow!("cannot read file list '{}': {}", list_path, e))?;
        content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else if !args.files.is_empty() {
        args.files.clone()
    } else {
        collect_files(".")
    };

    // Normalize paths and filter excluded files
    let files: Vec<String> = files
        .into_iter()
        .map(|f| f.strip_prefix("./").unwrap_or(&f).to_string())
        .filter(|f| !should_exclude(f, &excludes))
        .collect();

    // Get changed lines if base_sha is set and diff_only is enabled
    let changed = if let Some(sha) = base_sha.as_deref() {
        if policy.diff_only {
            get_changed_lines(sha)
        } else {
            None // scan all lines
        }
    } else {
        None
    };

    // Scan each file
    let mut all_findings = Vec::new();
    let mut scanned = 0usize;
    for path in &files {
        if !Path::new(path).is_file() {
            continue;
        }
        let changed_lines = changed.as_ref().and_then(|m| m.get(path.as_str()));
        all_findings.extend(scan_file(path, &policy, changed_lines, &excludes));
        scanned += 1;
    }

    if scanned == 0 {
        eprintln!("Warning: no files were scanned");
    }

    // Print findings
    let color = !args.no_color && std::io::stdout().is_terminal();
    for f in &all_findings {
        println!("{}", format_finding(f, color));
        println!();
    }
    println!("{}", format_summary(&all_findings, scanned));

    // Emit annotations
    if !args.no_annotations {
        emit_annotations(&all_findings);
    }

    // Write SARIF
    if let Some(ref sarif_path) = sarif_file {
        write_sarif(&all_findings, sarif_path)?;
        println!("SARIF report written to: {}", sarif_path);
    }

    // Write step summary and github outputs
    write_step_summary(&all_findings, scanned);
    write_github_outputs(&all_findings, scanned, sarif_file.as_deref());

    // Exit code
    let has_fail = all_findings.iter().any(|f| {
        let risk = policy.get_file_risk(&f.file);
        policy.should_fail(f.severity, risk)
    });
    let has_warn = all_findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Medium | Severity::Low));

    if has_fail || (args.fail_on_warn && has_warn) {
        process::exit(1);
    }

    Ok(())
}
