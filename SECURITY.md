# Security

Report a vulnerability privately through [GitHub private vulnerability reporting](https://github.com/falistos/agentsafe/security/advisories/new). Do not open a public issue for it.

## In scope

- A masking bypass for a value that appears in one of the spellings `run` and `scrub` cover: raw, base64 (standard and URL-safe, at the three alignments a value can have inside a larger blob), hexadecimal (lower and upper case), JSON as `serde_json` escapes it, also with non-ASCII characters as lower-case `\uXXXX` (surrogate pairs above U+FFFF, as Python's `json.dumps` writes them), with `/` as `\/`, or both, or percent-encoding with upper- or lower-case hex (`A-Z a-z 0-9 - . _ ~` left as is).
- An authentication or policy bypass on the server.
- A secret value written to command output, the audit log, or an error message.

## Out of scope

The threat model is accident prevention, not a sandbox. Out of scope:

- An agent that transforms a value on purpose before printing it (hashing, encrypting, reversing, printing it one character at a time, or an encoding that is not listed above).
- Any process running as the vault owner, including one that reads the age identity.
