mod iam;
mod normalize;

use anyhow::{Context, Result};
use clap::Parser;
use iam::load_policy;
use normalize::Normalize;
use serde_json::to_string_pretty;
use std::{fs::read_to_string, path::Path};

fn load(policy: &Path) -> Result<String, std::io::Error> {
    read_to_string(policy)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    path: std::path::PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let policy =
        load(&args.path).with_context(|| format!("Could not read file {}", args.path.display()))?;
    let policy = load_policy(&policy).with_context(|| {
        format!(
            "Failed to load data from {} as IAM Policy",
            args.path.display()
        )
    })?;
    let normalized_policy = policy.normalize();
    let normalized_policy = to_string_pretty(&normalized_policy)
        .context("Failed to deserialize Normalized IAM Policy")?;
    println!("{normalized_policy}");
    Ok(())
}
