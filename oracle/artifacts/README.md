# Local Java oracle artifact

Place the manifest-matching Java oracle JAR in this directory. JAR files are
ignored by Git because they contain large native and model resources. The
black-box launcher accepts only the `selected_sha256` in the freeze manifest.
The earlier user-provided incremental-build hash remains attested in the
provenance record, but is not a second executable oracle identity.
