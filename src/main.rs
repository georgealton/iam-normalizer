mod iam;
mod normalize;

use anyhow::{Context, Result};
use clap::Parser;
use iam::load_policy;
use normalize::Normalize;
use serde_json::to_string_pretty;
use std::{fs::read_to_string, path::Path};

fn load(policy: &str) -> Result<String, std::io::Error> {
    let path = Path::new(policy);
    read_to_string(path)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    policy_path: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let policy = load(&args.policy_path)
        .with_context(|| format!("Could not read file {}", args.policy_path))?;
    let policy = load_policy(&policy).context("Failed to load data as IAM Policy")?;
    let normalized_policy = policy.normalize();
    let normalized_policy = to_string_pretty(&normalized_policy)
        .context("Failed to deserialize Normalized IAM Policy")?;
    println!("{normalized_policy}");
    Ok(())
}
