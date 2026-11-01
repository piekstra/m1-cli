# Contributing

`m1-cli` is a member of the piekstra CLI family and conforms to the
`piekstra-cli/1` spec. Before changing the command surface, read
[`cli-common/DESIGN.md`](https://github.com/piekstra/cli-common/blob/main/DESIGN.md)
and [`conformance.md`](https://github.com/piekstra/cli-common/blob/main/conformance.md)
— the spec is the source of truth, not the code in any one sibling repo.

## The loop

```sh
make dev        # debug build, re-signed with the stable dev identity
make verify     # fmt-check + lint + test + smoke — exactly what CI runs
make install    # install to ~/.cargo/bin and re-sign
```

`make verify` is the gate. A green local run should predict a green CI run; if
it doesn't, that's a bug in the Makefile, not something to work around.

## Rules that are easy to break

**Tests are offline, always.** No test may make a network call or read the
keychain. M1's login flow can cost an MFA code and is rate-limited, so a test
suite that authenticates is a test suite nobody can run. Contract-test against
the JSON in `tests/fixtures/` instead.

**Fixtures are synthetic and stay synthetic.** See
[`tests/fixtures/README.md`](tests/fixtures/README.md). Never commit a raw
capture: bearer tokens and pre-signed document URLs are live credentials.
`fixture_shapes.rs` enforces the policy positively — identity-bearing fields
must match a known dummy shape.

**Never report success from an HTTP status.** M1's API is GraphQL: it answers
`200 OK` with an `errors` array for auth failures, bad queries, and rate limits
alike. Every response goes through the one envelope check in `src/client.rs`.
Adding a code path that inspects `response.status()` and nothing else is the
single most likely way to make this CLI lie. See `docs/api.md`.

**Reads only.** Every command is a read. If you add a write, it needs the §1.3
confirmation rules (prompt unless `--force`, exit 6 non-interactively) *and* an
update to `SECURITY.md` and `README.md` in the same commit.

**`--json` on everything.** One DTO per invocation, `schema`-tagged, on stdout;
diagnostics on stderr. If a command already emitted its DTO and then needs a
nonzero exit, exit directly rather than returning an error that would append a
second JSON document.

## Adding a command

1. A module in `src/commands/`, wired into the clap tree in `src/main.rs`.
2. Validate arguments **before** touching the keychain or the network, so
   `--help` and bad input never prompt, hang, or spend a request.
3. A `--help` render test in `tests/cli_surface.rs` (this is what catches a
   subcommand flag colliding with a global like `-q`).
4. A fixture + a shape test in `tests/fixture_shapes.rs` asserting the fields
   the table view actually reads, so an upstream rename fails loudly instead of
   silently emptying a column.
5. Document the endpoint — and any trap it taught you — in `docs/api.md`.

## Reverse-engineering notes

M1 publishes no public API, so everything here is derived from public community
sources and is subject to change without notice. If you verify a shape against
the live API, update `docs/api.md` and move the item out of the
**UNVERIFIED-LIVE** table in the same commit — that table is the honest record
of what has and hasn't been confirmed against a real account.
