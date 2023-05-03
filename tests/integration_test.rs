use anyhow::Result;
use std::{
    fs::{read_dir, read_to_string},
    path::Path,
    process::Command,
};

#[test]
fn test() -> Result<()> {
    let identity_policy_path = Path::new("./tests/data/policies/identity");
    let expect_path = Path::new("./tests/data/policies/identity/expect");

    for entry in read_dir(identity_policy_path)? {
        if let Ok(entry) = entry {
            if entry.path().is_file() {
                println!("{:?}", entry.file_name());
                let expected = read_to_string(expect_path.join(entry.file_name()))?;
                let bin = Path::new("target/debug/iam_normalizer");

                let mut command = Command::new(bin);
                let output = command.arg(entry.path()).output()?;
                let result = String::from_utf8(output.stdout)?.replace(" ", "");

                eprintln!("{}", String::from_utf8(output.stderr)?);
                assert!(output.status.success());
                assert_eq!(result, expected.replace(" ", ""));
            }
        }
    }

    Ok(())
}
