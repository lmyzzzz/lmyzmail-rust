# Three-language manual validation, 2026-10-23

The root `README.md` is the complete Chinese user manual. `README.en.md` and
`README.ja.md` provide the same functional, deployment, configuration, API and
operations coverage in English and Japanese. All three link to one another.
Historical migration logs remain in their existing documents and Git history.

Read-only source/example coverage checks found 273 distinct literal/example
configuration keys after normalizing indexed entries, domain names and rule
names. Every key is represented in each manual. All three have the same 279
documented key tokens, including aliases and parameterized families. The
tables also document dynamic domain/API-key/pot/trap/rule families. This is
an enumeration check plus focused source reading, not a proof that arbitrary
configuration values will start successfully.

Each manual was checked against all 72 method/path entries in the frozen
HTTP route manifest, with parameter names normalized. Static public resources
are documented as well. Three declared routes have no candidate success
handler: risk-IP list, statistics and detail. The manuals explicitly mark this
gap; G17–G19 in the remaining-work list keep the implementation and success
response differential checks open. The manifest's own count test is not
treated as behavior evidence.

All three manuals have 521 lines, 36 Markdown links and 10 fenced examples.
Local file/heading links, balanced fences, JSON examples and Bash syntax
checks passed. Translation checks found identical configuration and path
sets. `git diff --check` passed. Example initialization references the retained
DDL-only PostgreSQL schema. The unchanged release ELF also passed
`--config config/lmyzmail.properties.example --check-config` without opening
database connections or protocol listeners. Initialization does not import
test seed data; no database initialization,
installation, product build or new stress run was executed for this docs-only
change. These checks do not claim semantic equivalence of every translated
sentence or execution of the documented deployment commands.

The protected v2 calibration checkpoint and root terminal receipt were read
to correct the latest status summary. Its hash, size, 35-record JSONL format,
unqualified result and successful unqualified cleanup are recorded without
uploading the 279 MB raw checkpoint or altering its contents.

Product/native/oracle source, Cargo.lock, model weights, fixtures and historical
goldens are unchanged by this documentation change. Both frozen source
repositories remain read-only. The goal remains incomplete.
