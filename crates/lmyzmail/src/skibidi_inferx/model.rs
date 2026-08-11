use std::{collections::HashMap, fmt, fs::File, path::Path};

use bytemuck::try_cast_slice;
use memmap2::{Mmap, MmapOptions};
use safetensors::{Dtype, SafeTensors};

const MAX_MODEL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TENSORS: usize = 4_096;
const MAX_DIMENSION: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ModelDimensions {
    pub(crate) vocab_size: usize,
    pub(crate) d_model: usize,
    pub(crate) n_layers: usize,
    pub(crate) n_heads: usize,
    pub(crate) d_k: usize,
    pub(crate) d_ff: usize,
    pub(crate) max_seq_len: usize,
}

#[derive(Clone, Debug)]
struct TensorSpec {
    offset: usize,
    length: usize,
    shape: Vec<usize>,
}

#[derive(Clone, Debug)]
struct LayerSpecs {
    ln1: TensorSpec,
    qkv_weight: TensorSpec,
    qkv_bias: TensorSpec,
    out_weight: TensorSpec,
    out_bias: TensorSpec,
    ln2: TensorSpec,
    gate_weight: TensorSpec,
    gate_bias: TensorSpec,
    up_weight: TensorSpec,
    up_bias: TensorSpec,
    down_weight: TensorSpec,
    down_bias: TensorSpec,
}

pub(crate) struct ModelWeights {
    mapping: Mmap,
    dimensions: ModelDimensions,
    token_embedding: TensorSpec,
    position_embedding: TensorSpec,
    layers: Vec<LayerSpecs>,
    final_ln: TensorSpec,
}

impl ModelWeights {
    pub(crate) fn load(path: &Path) -> Result<Self, ModelError> {
        let file = File::open(path).map_err(ModelError::Io)?;
        let length = file.metadata().map_err(ModelError::Io)?.len();
        if !(9..=MAX_MODEL_BYTES).contains(&length) {
            return Err(ModelError::Invalid(format!(
                "InferX model size {length} is outside 9..={MAX_MODEL_BYTES}"
            )));
        }

        // SAFETY: the file is opened read-only and the mapping is retained for
        // every tensor slice. External replacement cannot violate memory
        // safety; SafeTensors validates the complete mapped byte structure.
        let mapping = unsafe { MmapOptions::new().map(&file) }.map_err(ModelError::Io)?;
        let tensors = SafeTensors::deserialize(&mapping).map_err(ModelError::SafeTensors)?;
        if tensors.is_empty() || tensors.len() > MAX_TENSORS {
            return Err(ModelError::Invalid(format!(
                "InferX tensor count {} is outside 1..={MAX_TENSORS}",
                tensors.len()
            )));
        }
        let (header_length, metadata) =
            SafeTensors::read_metadata(&mapping).map_err(ModelError::SafeTensors)?;
        let data_start = 8_usize
            .checked_add(header_length)
            .ok_or_else(|| ModelError::Invalid("InferX data offset overflow".into()))?;
        let metadata_values = metadata.metadata().as_ref();

        let dimensions = ModelDimensions {
            vocab_size: metadata_usize(metadata_values, "vocab_size", 6_969)?,
            d_model: metadata_usize(metadata_values, "d_model", 384)?,
            n_layers: metadata_usize(metadata_values, "n_layers", 8)?,
            n_heads: metadata_usize(metadata_values, "n_heads", 6)?,
            d_k: 0,
            d_ff: metadata_usize(metadata_values, "d_ff", 1_536)?,
            max_seq_len: metadata_usize(metadata_values, "max_seq_len", 128)?,
        };
        let dimensions = validate_dimensions(dimensions)?;

        let mut specs = HashMap::with_capacity(tensors.len());
        for (name, view) in tensors.iter() {
            if view.dtype() != Dtype::F32 {
                return Err(ModelError::Invalid(format!(
                    "InferX tensor {name:?} uses {:?}, expected F32",
                    view.dtype()
                )));
            }
            let relative = view
                .data()
                .as_ptr()
                .addr()
                .checked_sub(mapping.as_ptr().addr())
                .ok_or_else(|| ModelError::Invalid("InferX tensor offset underflow".into()))?;
            let byte_length = view.data().len();
            let end = relative
                .checked_add(byte_length)
                .filter(|end| *end <= mapping.len())
                .ok_or_else(|| ModelError::Invalid("InferX tensor range overflow".into()))?;
            if relative < data_start || end > mapping.len() || byte_length % 4 != 0 {
                return Err(ModelError::Invalid(format!(
                    "InferX tensor {name:?} has an invalid mapped range"
                )));
            }
            specs.insert(
                name.to_owned(),
                TensorSpec {
                    offset: relative,
                    length: byte_length,
                    shape: view.shape().to_vec(),
                },
            );
        }
        drop(tensors);

        let token_embedding = take_spec(
            &mut specs,
            "token_embedding.weight",
            &[dimensions.vocab_size, dimensions.d_model],
        )?;
        let position_embedding = take_spec(
            &mut specs,
            "position_embedding.weight",
            &[dimensions.max_seq_len, dimensions.d_model],
        )?;
        let final_ln = take_spec(&mut specs, "final_ln.weight", &[dimensions.d_model])?;
        let mut layers = Vec::with_capacity(dimensions.n_layers);
        for layer in 0..dimensions.n_layers {
            let prefix = format!("layers.{layer}");
            layers.push(LayerSpecs {
                ln1: take_spec(
                    &mut specs,
                    &format!("{prefix}.ln1.weight"),
                    &[dimensions.d_model],
                )?,
                qkv_weight: take_spec(
                    &mut specs,
                    &format!("{prefix}.attn.qkv_proj.weight"),
                    &[3 * dimensions.d_model, dimensions.d_model],
                )?,
                qkv_bias: take_spec(
                    &mut specs,
                    &format!("{prefix}.attn.qkv_proj.bias"),
                    &[3 * dimensions.d_model],
                )?,
                out_weight: take_spec(
                    &mut specs,
                    &format!("{prefix}.attn.out_proj.weight"),
                    &[dimensions.d_model, dimensions.d_model],
                )?,
                out_bias: take_spec(
                    &mut specs,
                    &format!("{prefix}.attn.out_proj.bias"),
                    &[dimensions.d_model],
                )?,
                ln2: take_spec(
                    &mut specs,
                    &format!("{prefix}.ln2.weight"),
                    &[dimensions.d_model],
                )?,
                gate_weight: take_spec(
                    &mut specs,
                    &format!("{prefix}.ffn.gate.weight"),
                    &[dimensions.d_ff, dimensions.d_model],
                )?,
                gate_bias: take_spec(
                    &mut specs,
                    &format!("{prefix}.ffn.gate.bias"),
                    &[dimensions.d_ff],
                )?,
                up_weight: take_spec(
                    &mut specs,
                    &format!("{prefix}.ffn.up.weight"),
                    &[dimensions.d_ff, dimensions.d_model],
                )?,
                up_bias: take_spec(
                    &mut specs,
                    &format!("{prefix}.ffn.up.bias"),
                    &[dimensions.d_ff],
                )?,
                down_weight: take_spec(
                    &mut specs,
                    &format!("{prefix}.ffn.down.weight"),
                    &[dimensions.d_model, dimensions.d_ff],
                )?,
                down_bias: take_spec(
                    &mut specs,
                    &format!("{prefix}.ffn.down.bias"),
                    &[dimensions.d_model],
                )?,
            });
        }
        if !specs.is_empty() {
            let mut names = specs.into_keys().collect::<Vec<_>>();
            names.sort();
            return Err(ModelError::Invalid(format!(
                "InferX model has unexpected tensors: {}",
                names.join(", ")
            )));
        }

        let model = Self {
            mapping,
            dimensions,
            token_embedding,
            position_embedding,
            layers,
            final_ln,
        };
        model.validate_alignment()?;
        Ok(model)
    }

    pub(crate) const fn dimensions(&self) -> ModelDimensions {
        self.dimensions
    }

    pub(crate) fn token_embedding(&self) -> &[f32] {
        self.tensor(&self.token_embedding)
    }

    pub(crate) fn position_embedding(&self) -> &[f32] {
        self.tensor(&self.position_embedding)
    }

    pub(crate) fn layer(&self, index: usize) -> LayerWeights<'_> {
        let specs = &self.layers[index];
        LayerWeights {
            ln1: self.tensor(&specs.ln1),
            qkv_weight: self.tensor(&specs.qkv_weight),
            qkv_bias: self.tensor(&specs.qkv_bias),
            out_weight: self.tensor(&specs.out_weight),
            out_bias: self.tensor(&specs.out_bias),
            ln2: self.tensor(&specs.ln2),
            gate_weight: self.tensor(&specs.gate_weight),
            gate_bias: self.tensor(&specs.gate_bias),
            up_weight: self.tensor(&specs.up_weight),
            up_bias: self.tensor(&specs.up_bias),
            down_weight: self.tensor(&specs.down_weight),
            down_bias: self.tensor(&specs.down_bias),
        }
    }

    pub(crate) fn final_ln(&self) -> &[f32] {
        self.tensor(&self.final_ln)
    }

    fn tensor(&self, spec: &TensorSpec) -> &[f32] {
        try_cast_slice(&self.mapping[spec.offset..spec.offset + spec.length])
            .expect("validated InferX F32 tensor alignment changed")
    }

    fn validate_alignment(&self) -> Result<(), ModelError> {
        let all_specs = std::iter::once(&self.token_embedding)
            .chain(std::iter::once(&self.position_embedding))
            .chain(std::iter::once(&self.final_ln))
            .chain(self.layers.iter().flat_map(|layer| {
                [
                    &layer.ln1,
                    &layer.qkv_weight,
                    &layer.qkv_bias,
                    &layer.out_weight,
                    &layer.out_bias,
                    &layer.ln2,
                    &layer.gate_weight,
                    &layer.gate_bias,
                    &layer.up_weight,
                    &layer.up_bias,
                    &layer.down_weight,
                    &layer.down_bias,
                ]
            }));
        for spec in all_specs {
            try_cast_slice::<u8, f32>(&self.mapping[spec.offset..spec.offset + spec.length])
                .map_err(|_| {
                    ModelError::Invalid("InferX F32 tensor is not naturally aligned".into())
                })?;
        }
        Ok(())
    }
}

pub(crate) struct LayerWeights<'a> {
    pub(crate) ln1: &'a [f32],
    pub(crate) qkv_weight: &'a [f32],
    pub(crate) qkv_bias: &'a [f32],
    pub(crate) out_weight: &'a [f32],
    pub(crate) out_bias: &'a [f32],
    pub(crate) ln2: &'a [f32],
    pub(crate) gate_weight: &'a [f32],
    pub(crate) gate_bias: &'a [f32],
    pub(crate) up_weight: &'a [f32],
    pub(crate) up_bias: &'a [f32],
    pub(crate) down_weight: &'a [f32],
    pub(crate) down_bias: &'a [f32],
}

fn metadata_usize(
    metadata: Option<&HashMap<String, String>>,
    key: &str,
    default: usize,
) -> Result<usize, ModelError> {
    let Some(value) = metadata.and_then(|values| values.get(key)) else {
        return Ok(default);
    };
    value.parse::<usize>().map_err(|_| {
        ModelError::Invalid(format!("InferX metadata {key:?} is not a positive integer"))
    })
}

fn validate_dimensions(mut value: ModelDimensions) -> Result<ModelDimensions, ModelError> {
    let fields = [
        ("vocab_size", value.vocab_size),
        ("d_model", value.d_model),
        ("n_layers", value.n_layers),
        ("n_heads", value.n_heads),
        ("d_ff", value.d_ff),
        ("max_seq_len", value.max_seq_len),
    ];
    for (name, field) in fields {
        if field == 0 || field > MAX_DIMENSION {
            return Err(ModelError::Invalid(format!(
                "InferX dimension {name}={field} is outside 1..={MAX_DIMENSION}"
            )));
        }
    }
    if !value.d_model.is_multiple_of(value.n_heads) {
        return Err(ModelError::Invalid(
            "InferX d_model is not divisible by n_heads".into(),
        ));
    }
    value.d_k = value.d_model / value.n_heads;
    if value.max_seq_len > 4_096 || value.n_layers > 256 || value.n_heads > 256 {
        return Err(ModelError::Invalid(
            "InferX architecture exceeds the runtime resource budget".into(),
        ));
    }
    Ok(value)
}

fn take_spec(
    specs: &mut HashMap<String, TensorSpec>,
    name: &str,
    shape: &[usize],
) -> Result<TensorSpec, ModelError> {
    let spec = specs
        .remove(name)
        .ok_or_else(|| ModelError::Invalid(format!("InferX tensor {name:?} is missing")))?;
    if spec.shape != shape {
        return Err(ModelError::Invalid(format!(
            "InferX tensor {name:?} has shape {:?}, expected {shape:?}",
            spec.shape
        )));
    }
    Ok(spec)
}

#[derive(Debug)]
pub(crate) enum ModelError {
    Io(std::io::Error),
    SafeTensors(safetensors::SafeTensorError),
    Invalid(String),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "InferX model I/O failed: {error}"),
            Self::SafeTensors(error) => write!(formatter, "InferX SafeTensors is invalid: {error}"),
            Self::Invalid(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for ModelError {}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NONCE: AtomicU64 = AtomicU64::new(0);

    fn temporary_model_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "lmyzmail-inferx-model-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn oversized_and_malformed_models_are_rejected_before_tensor_access() {
        let path = temporary_model_path();
        let oversized = File::create(&path).unwrap();
        oversized.set_len(MAX_MODEL_BYTES + 1).unwrap();
        drop(oversized);
        assert!(matches!(
            ModelWeights::load(&path),
            Err(ModelError::Invalid(_))
        ));

        fs::write(&path, [0_u8; 9]).unwrap();
        assert!(matches!(
            ModelWeights::load(&path),
            Err(ModelError::SafeTensors(_))
        ));
        fs::remove_file(path).unwrap();
    }
}
