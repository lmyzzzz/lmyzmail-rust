mod engine;
mod kernels;
mod model;
mod sampler;
mod service;
mod tokenizer;

pub use service::{InferxRuntimeInfo, InferxService, InsultResult};

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value;

    use super::{
        kernels::{Backend, SimdPreference},
        model::ModelWeights,
        sampler::{SamplingParams, seed_from_str},
        tokenizer::BpeTokenizer,
    };

    fn repository_path(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn golden() -> Value {
        serde_json::from_str(include_str!(
            "../../../../blackbox/golden/native/skibidi-inferx-java-v1/contract.json"
        ))
        .unwrap()
    }

    #[test]
    fn pinned_model_and_tokenizer_match_frozen_metadata_and_bpe_vectors() {
        let model = ModelWeights::load(&repository_path(
            "models/skibidi-inferx/skibidi_ai.safetensors",
        ))
        .unwrap();
        let tokenizer =
            BpeTokenizer::load(&repository_path("models/skibidi-inferx/tokenizer.json")).unwrap();
        let golden = golden();
        let dimensions = model.dimensions();
        assert_eq!(dimensions.vocab_size, golden["model"]["vocab_size"]);
        assert_eq!(dimensions.d_model, golden["model"]["d_model"]);
        assert_eq!(dimensions.n_layers, golden["model"]["n_layers"]);
        assert_eq!(dimensions.n_heads, golden["model"]["n_heads"]);
        assert_eq!(dimensions.d_k, golden["model"]["d_k"]);
        assert_eq!(dimensions.d_ff, golden["model"]["d_ff"]);
        assert_eq!(dimensions.max_seq_len, golden["model"]["max_seq_len"]);
        assert_eq!(tokenizer.vocab_size(), dimensions.vocab_size);

        for vector in golden["tokenizer"].as_array().unwrap() {
            let input = vector["input"].as_str().unwrap();
            let expected_ids = vector["ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as u32)
                .collect::<Vec<_>>();
            assert_eq!(tokenizer.encode(input), expected_ids);
            assert_eq!(
                tokenizer.decode(&expected_ids),
                vector["decoded"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn compact_model_is_hash_pinned_and_preserves_tokenizer_dimensions() {
        use sha2::{Digest, Sha256};
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../blackbox/golden/native/skibidi-inferx-compact-20261022/contract.json"
        ))
        .unwrap();
        for (relative, key) in [
            (
                "models/skibidi-inferx-compact-20261022/skibidi_ai.safetensors",
                "safetensors_sha256",
            ),
            ("models/skibidi-inferx/tokenizer.json", "tokenizer_sha256"),
        ] {
            let bytes = std::fs::read(repository_path(relative)).unwrap();
            assert_eq!(
                Sha256::digest(bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                contract["model"][key]
            );
        }
        let model = ModelWeights::load(&repository_path(
            "models/skibidi-inferx-compact-20261022/skibidi_ai.safetensors",
        ))
        .unwrap();
        let dimensions = model.dimensions();
        assert_eq!(dimensions.d_ff, 512);
        assert_eq!(dimensions.d_model, 384);
        assert_eq!(dimensions.n_layers, 8);
        assert_eq!(dimensions.n_heads, 6);
        assert_eq!(dimensions.max_seq_len, 128);
        assert_eq!(dimensions.vocab_size, 6969);
        assert_eq!(contract["tokenizer"], golden()["tokenizer"]);
    }

    #[test]
    fn exposed_sampling_defaults_are_valid_for_the_pinned_model() {
        let model = ModelWeights::load(&repository_path(
            "models/skibidi-inferx-compact-20261022/skibidi_ai.safetensors",
        ))
        .unwrap();
        let params = SamplingParams {
            temperature: 0.85,
            top_k: 50,
            top_p: 0.92,
            repetition_penalty: 1.15,
            no_repeat_ngram: 3,
        };
        params.validate(model.dimensions().vocab_size).unwrap();
        assert_eq!(seed_from_str(""), 0x141c_fc98_42c4_b0e3);
        let backend = Backend::select(SimdPreference::Auto).unwrap();
        assert!(!backend.name().is_empty());
    }
}
