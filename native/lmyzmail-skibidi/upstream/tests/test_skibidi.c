#include "skibidi_avx.h"

#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s (line %d)\n", (message), __LINE__); \
        return 1; \
    } \
} while (0)

static const char PROPHECY[] = "Skibidi dop dop dop yes yes!";

typedef struct {
    uint64_t generated;
    uint64_t prophecy;
    uint64_t prefix;
    uint64_t dop_counts[6];
    uint64_t dop_words;
    uint64_t dom_words;
    uint64_t uppercase_dop_words;
    uint64_t approval;
    uint64_t rejection;
    uint64_t fifth_dop;
    uint64_t fifth_dop_variant;
    uint64_t bytes;
    int min_length;
    int max_length;
} OutputStats;

static int token_is_dop_or_dom(const char* token, size_t length) {
    if (length != 3) return 0;
    const int a = tolower((unsigned char)token[0]);
    const int b = tolower((unsigned char)token[1]);
    const int c = tolower((unsigned char)token[2]);
    return a == 'd' && b == 'o' && (c == 'p' || c == 'm');
}

static int token_case_equal(const char* token, size_t length, const char* word) {
    const size_t word_length = strlen(word);
    if (length != word_length) return 0;
    for (size_t i = 0; i < length; i++) {
        if (tolower((unsigned char)token[i]) !=
            tolower((unsigned char)word[i])) return 0;
    }
    return 1;
}

static int inspect_output(const char* output, int length, OutputStats* stats) {
    const char* tokens[7];
    size_t token_lengths[7];
    int token_count = 0;
    const char* cursor = output;
    const char* end = output + length;
    const int has_prefix =
        end - cursor >= 7 && memcmp(cursor, "Brrrrr ", 7) == 0;
    if (has_prefix) cursor += 7;
    if (end - cursor < 8 || memcmp(cursor, "Skibidi ", 8) != 0) return 0;
    cursor += 8;

    while (cursor < end) {
        if (token_count == 7) return 0;
        const char* space = memchr(cursor, ' ', (size_t)(end - cursor));
        const char* token_end = space ? space : end;
        if (token_end == cursor) return 0;
        tokens[token_count] = cursor;
        token_lengths[token_count] = (size_t)(token_end - cursor);
        token_count++;
        if (!space) break;
        cursor = space + 1;
    }

    if (token_count < 3 || token_count > 7) return 0;
    const int dop_count = token_count - 2;
    for (int i = 0; i < dop_count; i++) {
        if (!token_is_dop_or_dom(tokens[i], token_lengths[i])) return 0;
    }

    const char* final = tokens[token_count - 1];
    const size_t final_length = token_lengths[token_count - 1];
    if (final_length < 2 || final[final_length - 1] != '!') return 0;
    const char* first_ending = tokens[token_count - 2];
    const size_t first_ending_length = token_lengths[token_count - 2];
    const int approval =
        token_case_equal(first_ending, first_ending_length, "yes") &&
        token_case_equal(final, final_length - 1, "yes");
    const int rejection =
        token_case_equal(first_ending, first_ending_length, "no") &&
        token_case_equal(final, final_length - 1, "no");
    if (!approval && !rejection) return 0;

    stats->generated++;
    stats->bytes += (uint64_t)length;
    stats->prefix += (uint64_t)has_prefix;
    stats->approval += (uint64_t)approval;
    stats->rejection += (uint64_t)rejection;
    stats->dop_counts[dop_count]++;
    stats->dop_words += (uint64_t)dop_count;
    if (length < stats->min_length) stats->min_length = length;
    if (length > stats->max_length) stats->max_length = length;
    if (length == (int)(sizeof(PROPHECY) - 1) &&
        memcmp(output, PROPHECY, sizeof(PROPHECY) - 1) == 0) {
        stats->prophecy++;
    }

    for (int i = 0; i < dop_count; i++) {
        const int uppercase =
            isupper((unsigned char)tokens[i][0]) ||
            isupper((unsigned char)tokens[i][1]) ||
            isupper((unsigned char)tokens[i][2]);
        stats->dom_words +=
            (uint64_t)(tolower((unsigned char)tokens[i][2]) == 'm');
        stats->uppercase_dop_words += (uint64_t)uppercase;
        if (i == 4) {
            stats->fifth_dop++;
            stats->fifth_dop_variant += (uint64_t)uppercase;
        }
    }
    return 1;
}

static int within_binomial_sigma(
    uint64_t observed, uint64_t samples, double probability, double sigma)
{
    const double expected = (double)samples * probability;
    const double deviation = fabs((double)observed - expected);
    const double standard_deviation =
        sqrt((double)samples * probability * (1.0 - probability));
    return deviation <= sigma * standard_deviation + 1.0;
}

static uint64_t distribution_iterations(void) {
    const char* configured = getenv("SKIBIDI_DISTRIBUTION_SAMPLES");
    if (!configured || !*configured) return UINT64_C(10000000);
    char* end = NULL;
    const unsigned long long parsed = strtoull(configured, &end, 10);
    if (!end || *end != '\0' || parsed < UINT64_C(100000)) {
        return UINT64_C(10000000);
    }
    return (uint64_t)parsed;
}

static int test_api_and_determinism(void) {
    CHECK(skibidi_init(NULL, 1) == SKIBIDI_ERR_NULL_PTR, "NULL init must fail");

    SkibidiContext first;
    SkibidiContext second;
    char first_output[SKIBIDI_MIN_BUFFER_SIZE];
    char second_output[SKIBIDI_MIN_BUFFER_SIZE];

    CHECK(skibidi_init(&first, UINT64_C(0x123456789abcdef0)) == SKIBIDI_OK,
          "first context init");
    CHECK(skibidi_init(&second, UINT64_C(0x123456789abcdef0)) == SKIBIDI_OK,
          "second context init");
    CHECK(skibidi_generate(&first, NULL, sizeof(first_output)) == SKIBIDI_ERR_NULL_PTR,
          "NULL output must fail");
    CHECK(skibidi_generate(&first, first_output, 63) == SKIBIDI_ERR_BUFFER_TOO_SMALL,
          "small output must fail");

    for (int i = 0; i < 10000; i++) {
        int first_length = skibidi_generate(&first, first_output, sizeof(first_output));
        int second_length = skibidi_generate(&second, second_output, sizeof(second_output));
        CHECK(first_length == second_length, "same seed length mismatch");
        CHECK(memcmp(first_output, second_output, (size_t)first_length) == 0,
              "same seed output mismatch");
    }
    CHECK(memcmp(&first.rng, &second.rng, sizeof(first.rng)) == 0,
          "same seed state mismatch");
    return 0;
}

static int rng_lanes_are_nonzero(const SkibidiRngState* rng) {
    for (int lane = 0; lane < 4; lane++) {
        if ((rng->s0[lane] | rng->s1[lane]) == 0) return 0;
    }
    return 1;
}

static int test_boundary_contracts(void) {
    struct {
        unsigned char before[32];
        char output[SKIBIDI_MIN_BUFFER_SIZE];
        unsigned char after[32];
    } single;
    SkibidiContext ctx;
    OutputStats stats = {.min_length = 1000};

    memset(&single, 0xa5, sizeof(single));
    CHECK(skibidi_init(&ctx, 7) == SKIBIDI_OK, "boundary single init");
    int length = skibidi_generate(&ctx, single.output, sizeof(single.output));
    CHECK(length >= 18 && length <= 43, "exact-size single generation failed");
    CHECK(inspect_output(single.output, length, &stats),
          "exact-size single output invalid");
    for (size_t i = 0; i < sizeof(single.before); i++) {
        CHECK(single.before[i] == 0xa5, "single wrote before buffer");
        CHECK(single.after[i] == 0xa5, "single wrote after buffer");
    }

    SkibidiContext snapshot = ctx;
    memset(single.output, 0xa5, sizeof(single.output));
    CHECK(skibidi_generate(&ctx, single.output, 63) ==
              SKIBIDI_ERR_BUFFER_TOO_SMALL,
          "63-byte single buffer must fail");
    CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0,
          "failed single call advanced context");
    for (size_t i = 0; i < sizeof(single.output); i++) {
        CHECK((unsigned char)single.output[i] == 0xa5,
              "failed single call wrote output");
    }

    struct {
        unsigned char before[32];
        char output[4 * 44];
        unsigned char after[32];
    } batch;
    int guarded_lengths[6] = {-1, -2, -2, -2, -2, -1};
    memset(&batch, 0xa5, sizeof(batch));
    CHECK(skibidi_init(&ctx, 8) == SKIBIDI_OK, "boundary batch init");
    int generated = skibidi_generate_batch(
        &ctx, batch.output, sizeof(batch.output), 4, &guarded_lengths[1]);
    CHECK(generated == 4, "exact-capacity batch did not generate four records");
    CHECK(ctx.call_count == 4, "exact-capacity batch call_count mismatch");
    CHECK(guarded_lengths[0] == -1 && guarded_lengths[5] == -1,
          "batch lengths wrote outside requested range");
    size_t offset = 0;
    memset(&stats, 0, sizeof(stats));
    stats.min_length = 1000;
    for (int i = 0; i < generated; i++) {
        CHECK(inspect_output(
                  batch.output + offset, guarded_lengths[i + 1], &stats),
              "exact-capacity batch output invalid");
        CHECK(batch.output[offset + (size_t)guarded_lengths[i + 1]] == '\n',
              "exact-capacity batch newline missing");
        offset += (size_t)guarded_lengths[i + 1] + 1;
    }
    CHECK(offset <= sizeof(batch.output), "batch compact output exceeds capacity");
    for (size_t i = 0; i < sizeof(batch.before); i++) {
        CHECK(batch.before[i] == 0xa5, "batch wrote before buffer");
        CHECK(batch.after[i] == 0xa5, "batch wrote after buffer");
    }

    snapshot = ctx;
    memset(batch.output, 0xa5, sizeof(batch.output));
    CHECK(skibidi_generate_batch(&ctx, batch.output, 63, 4, NULL) == 0,
          "63-byte batch buffer must fail");
    CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0,
          "failed batch call advanced context");
    for (size_t i = 0; i < sizeof(batch.output); i++) {
        CHECK((unsigned char)batch.output[i] == 0xa5,
              "failed batch call wrote output");
    }
    return 0;
}

static int test_batch_determinism_and_rng_lifetime(void) {
    enum { DETERMINISM_COUNT = 4096, RNG_BATCH_COUNT = 64 };
    const size_t capacity = (size_t)DETERMINISM_COUNT * 44;
    char* first_output = malloc(capacity);
    char* second_output = malloc(capacity);
    int* first_lengths = malloc(DETERMINISM_COUNT * sizeof(*first_lengths));
    int* second_lengths = malloc(DETERMINISM_COUNT * sizeof(*second_lengths));
    CHECK(first_output && second_output && first_lengths && second_lengths,
          "batch determinism allocation");

    SkibidiConfig config = {0};
    config.enable_simd_rng = 1;
    CHECK(skibidi_configure(&config) == SKIBIDI_OK,
          "batch determinism configure");
    SkibidiContext first;
    SkibidiContext second;
    CHECK(skibidi_init(&first, UINT64_C(0xfedcba9876543210)) == SKIBIDI_OK,
          "first batch determinism init");
    CHECK(skibidi_init(&second, UINT64_C(0xfedcba9876543210)) == SKIBIDI_OK,
          "second batch determinism init");
    const int first_count = skibidi_generate_batch(
        &first, first_output, capacity, DETERMINISM_COUNT, first_lengths);
    const int second_count = skibidi_generate_batch(
        &second, second_output, capacity, DETERMINISM_COUNT, second_lengths);
    CHECK(first_count == DETERMINISM_COUNT && second_count == DETERMINISM_COUNT,
          "batch determinism generated count mismatch");
    CHECK(memcmp(first_lengths, second_lengths, sizeof(*first_lengths) *
                     DETERMINISM_COUNT) == 0,
          "same-seed batch lengths differ");
    size_t used = 0;
    for (int i = 0; i < DETERMINISM_COUNT; i++) {
        used += (size_t)first_lengths[i] + 1;
    }
    CHECK(memcmp(first_output, second_output, used) == 0,
          "same-seed batch bytes differ");
    CHECK(memcmp(&first.rng, &second.rng, sizeof(first.rng)) == 0,
          "same-seed batch RNG states differ");
    CHECK(first.call_count == DETERMINISM_COUNT &&
              second.call_count == DETERMINISM_COUNT,
          "same-seed batch call_count mismatch");
    CHECK(rng_lanes_are_nonzero(&first.rng),
          "batch determinism RNG reached all-zero lane");

    char rng_output[RNG_BATCH_COUNT * 44];
    int rng_lengths[RNG_BATCH_COUNT];
    CHECK(skibidi_init(&first, 9) == SKIBIDI_OK, "long-run RNG init");
    const int iterations = 1000000 / RNG_BATCH_COUNT;
    for (int i = 0; i < iterations; i++) {
        CHECK(skibidi_generate_batch(
                  &first, rng_output, sizeof(rng_output),
                  RNG_BATCH_COUNT, rng_lengths) == RNG_BATCH_COUNT,
              "long-run RNG batch generation failed");
        CHECK(rng_lanes_are_nonzero(&first.rng),
              "long-run RNG reached all-zero lane");
    }
    CHECK(first.call_count == (uint64_t)iterations * RNG_BATCH_COUNT,
          "long-run RNG call_count mismatch");

    free(second_lengths);
    free(first_lengths);
    free(second_output);
    free(first_output);
    return 0;
}

static int test_single_distributions(void) {
    SkibidiContext ctx;
    char output[SKIBIDI_MIN_BUFFER_SIZE];
    OutputStats stats = {.min_length = 1000};
    const uint64_t iterations = distribution_iterations();
    const double six_sigma = 6.0;
    const double direct_prophecy =
        1680443541.0 / 4294967296.0;
    const double total_prophecy = 0.4000000000606502;
    const double natural_prophecy = 0.014359547351096985;
    const double random_prefix = 38.0 / 256.0;
    const double approval_probability = 218.0 / 256.0;

    CHECK(skibidi_init(&ctx, 12345) == SKIBIDI_OK, "distribution init");
    for (uint64_t i = 0; i < iterations; i++) {
        int length = skibidi_generate(&ctx, output, sizeof(output));
        CHECK(length >= 18 && length <= 43, "generate length out of range");
        CHECK(inspect_output(output, length, &stats),
              "generate output structure invalid");
    }

    double average_length = (double)stats.bytes / (double)iterations;
    CHECK(within_binomial_sigma(
              stats.prophecy, iterations, total_prophecy, six_sigma),
          "prophecy probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.prefix, iterations,
              (1.0 - direct_prophecy) * random_prefix, six_sigma),
          "generate prefix probability outside fixed six-sigma bound");
    CHECK(average_length > 26.5 && average_length < 26.9,
          "generate average length regression");
    CHECK(stats.min_length == 18 && stats.max_length == 43,
          "generate did not reach both length extremes");
    CHECK((ctx.rng.s0[0] | ctx.rng.s1[0]) != 0,
          "single RNG collapsed to all zero");

    memset(&stats, 0, sizeof(stats));
    stats.min_length = 1000;
    CHECK(skibidi_init(&ctx, 12345) == SKIBIDI_OK, "variant init");
    for (uint64_t i = 0; i < iterations; i++) {
        int length = skibidi_generate_variant(&ctx, output, sizeof(output));
        CHECK(length >= 18 && length <= 43, "variant length out of range");
        CHECK(inspect_output(output, length, &stats),
              "variant output structure invalid");
    }

    average_length = (double)stats.bytes / (double)iterations;
    CHECK(within_binomial_sigma(
              stats.prophecy, iterations, natural_prophecy, six_sigma),
          "natural prophecy probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.prefix, iterations, random_prefix, six_sigma),
          "variant prefix probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.approval, iterations, approval_probability, six_sigma),
          "approval probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.dop_counts[1], iterations, 13.0 / 256.0, six_sigma),
          "one-dop probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.dop_counts[2], iterations, 192.0 / 256.0, six_sigma),
          "two-dop probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.dop_counts[3], iterations, 26.0 / 256.0, six_sigma),
          "three-dop probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.dop_counts[4], iterations, 13.0 / 256.0, six_sigma),
          "four-dop probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.dop_counts[5], iterations, 12.0 / 256.0, six_sigma),
          "five-dop probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.dom_words, stats.dop_words, 1.0 / 8.0, six_sigma),
          "dom probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.uppercase_dop_words, stats.dop_words,
              7.0 / 32.0, six_sigma),
          "dop case probability outside fixed six-sigma bound");
    CHECK(within_binomial_sigma(
              stats.fifth_dop_variant, stats.fifth_dop,
              7.0 / 32.0, six_sigma),
          "fifth-dop case probability outside fixed six-sigma bound");
    CHECK(average_length > 25.7 && average_length < 26.1,
          "variant average length regression");
    CHECK(stats.rejection > 0 && stats.dom_words > 0 &&
              stats.fifth_dop > 0 && stats.fifth_dop_variant > 0,
          "variant rare paths were not reached");
    CHECK(stats.min_length == 18 && stats.max_length == 43,
          "variant did not reach both length extremes");
    CHECK((ctx.rng.s0[0] | ctx.rng.s1[0]) != 0,
          "variant RNG collapsed to all zero");
    return 0;
}

static int run_batch_case(int simd_enabled) {
    const int count = 200000;
    const size_t capacity = (size_t)count * SKIBIDI_MIN_BUFFER_SIZE;
    unsigned char* storage = malloc(capacity + 64);
    int* lengths = malloc((size_t)count * sizeof(*lengths));
    CHECK(storage != NULL && lengths != NULL, "batch allocation");
    memset(storage, 0, capacity);
    memset(storage + capacity, 0xa5, 64);

    SkibidiConfig config = {0};
    config.enable_simd_rng = simd_enabled;
    CHECK(skibidi_configure(&config) == SKIBIDI_OK, "batch configure");
    SkibidiConfig observed = {0};
    CHECK(skibidi_get_config(&observed) == SKIBIDI_OK, "get batch config");
    CHECK(observed.enable_simd_rng == simd_enabled, "SIMD RNG config ignored");

    SkibidiContext ctx;
    CHECK(skibidi_init(&ctx, 42) == SKIBIDI_OK, "batch init");
    uint64_t untouched_s0[3];
    uint64_t untouched_s1[3];
    memcpy(untouched_s0, &ctx.rng.s0[1], sizeof(untouched_s0));
    memcpy(untouched_s1, &ctx.rng.s1[1], sizeof(untouched_s1));

    int generated = skibidi_generate_batch(
        &ctx, (char*)storage, capacity, count, lengths);
    CHECK(generated == count, "batch generated fewer records than requested");
    CHECK(ctx.call_count == (uint64_t)count, "batch call_count mismatch");

    const int active_vector_batch =
        simd_enabled && strcmp(skibidi_get_active_simd(), "Scalar") != 0;
    if (!active_vector_batch) {
        CHECK(memcmp(untouched_s0, &ctx.rng.s0[1], sizeof(untouched_s0)) == 0,
              "scalar batch changed secondary s0 lanes");
        CHECK(memcmp(untouched_s1, &ctx.rng.s1[1], sizeof(untouched_s1)) == 0,
              "scalar batch changed secondary s1 lanes");
    } else {
        CHECK(memcmp(untouched_s0, &ctx.rng.s0[1], sizeof(untouched_s0)) != 0,
              "SIMD batch did not advance secondary s0 lanes");
        CHECK(memcmp(untouched_s1, &ctx.rng.s1[1], sizeof(untouched_s1)) != 0,
              "SIMD batch did not advance secondary s1 lanes");
    }

    OutputStats stats = {.min_length = 1000};
    size_t offset = 0;
    for (int i = 0; i < generated; i++) {
        CHECK(lengths[i] >= 18 && lengths[i] <= 43, "batch length out of range");
        CHECK(inspect_output(
                  (const char*)storage + offset, lengths[i], &stats),
              "batch output structure invalid");
        CHECK(storage[offset + (size_t)lengths[i]] == '\n', "missing batch newline");
        offset += (size_t)lengths[i] + 1;
    }
    for (size_t i = 0; i < 64; i++) {
        CHECK(storage[capacity + i] == 0xa5, "batch wrote beyond capacity");
    }

    double prophecy_rate = (double)stats.prophecy / (double)stats.generated;
    double prefix_rate = (double)stats.prefix / (double)stats.generated;
    double average_length = (double)stats.bytes / (double)stats.generated;
    CHECK(prophecy_rate > 0.39 && prophecy_rate < 0.41,
          "batch prophecy probability regression");
    CHECK(prefix_rate > 0.08 && prefix_rate < 0.10,
          "batch prefix path is unreachable or biased");
    CHECK(average_length > 26.3 && average_length < 27.1,
          "batch average length regression");
    CHECK(stats.fifth_dop > 1000, "batch did not exercise fifth-dop path");
    CHECK(stats.fifth_dop_variant > 100,
          "batch fifth-dop case variants are unreachable");

    free(lengths);
    free(storage);
    return 0;
}

int main(void) {
    CHECK(sizeof(SkibidiContext) == 192, "context ABI size changed");
    CHECK(_Alignof(SkibidiContext) == 64, "context ABI alignment changed");
    CHECK(test_api_and_determinism() == 0, "API/determinism test");
    CHECK(test_boundary_contracts() == 0, "boundary contract test");
    CHECK(test_batch_determinism_and_rng_lifetime() == 0,
          "batch determinism/RNG lifetime test");
    CHECK(test_single_distributions() == 0, "single distribution test");
    CHECK(run_batch_case(0) == 0, "scalar batch test");
    CHECK(run_batch_case(1) == 0, "SIMD batch test");
    printf("PASS: API, RNG lifetime, distributions, and batch paths "
           "distribution_samples=%" PRIu64 "\n",
           distribution_iterations());
    return 0;
}
