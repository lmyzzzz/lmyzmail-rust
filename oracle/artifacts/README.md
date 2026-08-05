# Local Java oracle artifact

Place the manifest-matching Java oracle JAR in this directory. JAR files are
ignored by Git because they contain large native and model resources. The
black-box launcher rejects an artifact whose SHA-256 is not explicitly listed
in the freeze manifest.

