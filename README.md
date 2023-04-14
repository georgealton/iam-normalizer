# IAM Policy Normalizer

Takes your IAM policies and makes their output consistent and eaier to read.

- Actions and Resources are always alphabetically sorted unique lists
- Condition Keys should be lowercase

## Action

- [x] are unique lists
- [x] are unique lowercase
- [x] are unique
- [x] are sorted alphabetically

## Resource

- [x] are unique lists
- [x] are unique lowercase
- [x] are unique
- [x] are sorted alphabetically

## Condition

- [x] Condition Keys are lowercase 

## Principal

- [x] wildcard is unchanged
- [x] are unique lists
- [x] are unique lowercase
- [x] are unique
- [x] are sorted alphabetically

## Effect

- [x] Not Changed

## Sid

- [x] Not Changed

## Id

- [x] Not Changed

## Version

- [x] Not Changed


https://steampipe.io/blog/normalizing-aws-iam--for-automated-analysis
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html#policies-grammar-bnf
