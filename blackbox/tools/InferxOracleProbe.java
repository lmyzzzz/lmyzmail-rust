package net.lmyz.lmyzmail.skibidi_inferx;

import java.nio.file.Path;
import java.util.List;

public final class InferxOracleProbe {
    private static final List<String> TOKENIZER_INPUTS = List.of(
        "5.7.1 Go back to Ohio.",
        "ratio'd \"Skibidi\" [NO]",
        "mail@example.test",
        "邮件:Ohio:💀"
    );

    private static final List<String> GENERATION_INPUTS = List.of(
        "203.0.113.7:<spoof@example.test>:1700000000000",
        "",
        "邮件:Ohio:💀"
    );

    private InferxOracleProbe() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length > 3) {
            throw new IllegalArgumentException(
                "usage: InferxOracleProbe MODEL TOKENIZER [SIMD_LEVEL]");
        }
        int simdLevel = args.length == 3 ? Integer.parseInt(args[2]) : 0;
        NativeOps.initWithLevel(simdLevel);
        BpeTokenizer tokenizer = BpeTokenizer.load(Path.of(args[1]));
        try (InferenceEngine engine = new InferenceEngine(Path.of(args[0]), Path.of(args[1]))) {
            ModelWeights weights = engine.getWeights();
            StringBuilder out = new StringBuilder();
            out.append("{\n");
            field(out, "simd", NativeOps.simdLevelName(), true);
            out.append("  \"model\": {");
            out.append("\"vocab_size\":").append(weights.vocabSize()).append(',');
            out.append("\"d_model\":").append(weights.dModel()).append(',');
            out.append("\"n_layers\":").append(weights.nLayers()).append(',');
            out.append("\"n_heads\":").append(weights.nHeads()).append(',');
            out.append("\"d_k\":").append(weights.dK()).append(',');
            out.append("\"d_ff\":").append(weights.dFf()).append(',');
            out.append("\"max_seq_len\":").append(weights.maxSeqLen()).append("},\n");
            out.append("  \"tokenizer\": [\n");
            for (int i = 0; i < TOKENIZER_INPUTS.size(); i++) {
                String input = TOKENIZER_INPUTS.get(i);
                List<Integer> ids = tokenizer.encode(input);
                out.append("    {\"input\":").append(quote(input))
                    .append(",\"ids\":").append(ids)
                    .append(",\"decoded\":").append(quote(tokenizer.decode(ids))).append('}');
                out.append(i + 1 == TOKENIZER_INPUTS.size() ? "\n" : ",\n");
            }
            out.append("  ],\n");
            out.append("  \"generation\": [\n");
            for (int i = 0; i < GENERATION_INPUTS.size(); i++) {
                String input = GENERATION_INPUTS.get(i);
                InferenceEngine.GenerationResult result = engine.generateWithInfo(input);
                out.append("    {\"input\":").append(quote(input))
                    .append(",\"seed_hex\":").append(quote(SeedUtil.seedToHex(result.seed())))
                    .append(",\"token_count\":").append(result.tokenCount())
                    .append(",\"text\":").append(quote(result.text())).append('}');
                out.append(i + 1 == GENERATION_INPUTS.size() ? "\n" : ",\n");
            }
            out.append("  ]\n");
            out.append("}\n");
            System.out.print(out);
        }
    }

    private static void field(StringBuilder out, String name, String value, boolean comma) {
        out.append("  ").append(quote(name)).append(':').append(quote(value));
        out.append(comma ? ",\n" : "\n");
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder(value.length() + 16);
        out.append('"');
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }
}
