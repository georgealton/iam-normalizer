use anyhow::Result;
use std::{
    fs::{read_dir, read_to_string},
    path::Path,
    process::Command,
};

#[test]
fn test_identity() -> Result<()> {
    let identity_policy_path = Path::new("./tests/data/policies/identity/");

    for entry in read_dir(identity_policy_path)? {
        if let Ok(entry) = entry {
            if entry.path().is_dir() {
                let dir = entry.path();
                let input = entry.path().join("input.json");
                let expect = read_to_string(dir.join("expect.json"))?;

                let bin = Path::new("target/debug/iam_normalizer");
                let mut command = Command::new(bin);
                let output = command.arg(input).output()?;
                let result = String::from_utf8(output.stdout)?
                    .split_whitespace()
                    .collect::<String>();

                eprintln!("{}", String::from_utf8(output.stderr)?);
                assert!(output.status.success(), "Command Failed");
                assert_eq!(result, expect.split_whitespace().collect::<String>());
            }
        }
    }

    Ok(())
}

#[test]
fn test_resource() -> Result<()> {
    let identity_policy_path = Path::new("./tests/data/policies/resource/");

    for entry in read_dir(identity_policy_path)? {
        if let Ok(entry) = entry {
            if entry.path().is_dir() {
                let dir = entry.path();
                let input = entry.path().join("input.json");
                let expect = read_to_string(dir.join("expect.json"))?;

                let bin = Path::new("target/debug/iam_normalizer");
                let mut command = Command::new(bin);
                let output = command.arg(input).output()?;
                let result = String::from_utf8(output.stdout)?
                    .split_whitespace()
                    .collect::<String>();

                eprintln!("{}", String::from_utf8(output.stderr)?);
                assert!(output.status.success(), "Command Failed");
                assert_eq!(result, expect.split_whitespace().collect::<String>());
            }
        }
    }

    Ok(())
}
