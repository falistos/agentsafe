# Security

Report a vulnerability privately through [GitHub private vulnerability reporting](https://github.com/falistos/agentsafe/security/advisories/new). Do not open a public issue for it.

## In scope

- A masking bypass for a value that appears in one of the spellings `run` and `scrub` cover: raw, base64 (standard and URL-safe, at the three alignments a value can have inside a larger blob), hexadecimal (lower and upper case), JSON as `serde_json` escapes it, or percent-encoding with upper-case hex. Other JSON escapes (`\uXXXX` for non-ASCII, `\/`) and lower-case percent escapes are known gaps ([#9](https://github.com/falistos/agentsafe/issues/9)).
- An authentication or policy bypass on the server.
- A secret value written to command output, the audit log, or an error message.

## Out of scope

The threat model is accident prevention, not a sandbox. Out of scope:

- An agent that transforms a value on purpose before printing it (hashing, encrypting, reversing, printing it one character at a time, or an encoding that is not listed above).
- Any process running as the vault owner, including one that reads the age identity.
