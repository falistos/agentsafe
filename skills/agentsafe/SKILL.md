---
name: agentsafe
description: Secrets through agentsafe. Use when a command needs a token, password or key, when storing or rotating one, or when a `.env` or secret file comes up.
---

Secret values live in agentsafe. You work with entry **names**; values reach only the commands you
run, and their output comes back to you masked as `***NAME***`.

## Find

- `agentsafe list`: every entry, with its description, owner, tags and rotation date.
- `agentsafe describe NAME`: one entry's key names, and which keys are too short to be masked.

## Use

```sh
agentsafe run --env NAME -- CMD ARGS               # every key of NAME as a variable
agentsafe run --env NAME:KEY=VAR -- CMD ARGS       # one key, under another variable name
agentsafe run --env a --env b -- sh -c 'curl -H "Authorization: Bearer $A_TOKEN" … | jq …'
```

Put pipes and `$VAR` inside `sh -c '...'`, so that the child expands them. `sh`, not your login
shell, which may reset the variables from its startup files.

A file that needs a value (a config, an env file): write a template with
`{{ secrets["NAME"].KEY }}`, then `agentsafe render TEMPLATE --allow NAME -o FILE`, which writes it
0600. Hand the file to the program; leave its content unread.

Output that may hold values from elsewhere (a log, a file a command wrote): pipe it through
`agentsafe scrub`.

## Store and rotate

Values go in through stdin, so they never sit in a command line or your transcript:

```sh
CMD_THAT_PRINTS_THE_TOKEN | agentsafe set NAME --key KEY --description "what it is for"
agentsafe set NAME --key KEY < FILE
agentsafe import FILE.env --name NAME
```

`set --key` changes that key only. A value you must type yourself is the owner's to enter: ask them
to run the `set` command.

## When it says no

`***NAME***` in output is the mask doing its job: keep it masked, and work from the command's exit
code and the rest of its output. A refusal (`403`, `not allowed`, `no grant`) is the owner's
access policy: report which entry and action you need, and let them grant it.
