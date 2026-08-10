#include "skibidi_avx.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    PROBE_SINGLE_COUNT = 8,
    PROBE_BATCH_COUNT = 8,
    PROBE_BATCH_CAPACITY = PROBE_BATCH_COUNT * 44
};

static void print_expression(const char *bytes, int length) {
    putchar('"');
    fwrite(bytes, 1, (size_t)length, stdout);
    putchar('"');
}

static void print_single_sequence(uint64_t seed, int variant) {
    SkibidiContext context;
    char output[SKIBIDI_MIN_BUFFER_SIZE];

    if (skibidi_init(&context, seed) != SKIBIDI_OK) {
        fputs("null", stdout);
        return;
    }

    putchar('[');
    for (int index = 0; index < PROBE_SINGLE_COUNT; index++) {
        const int length = variant
            ? skibidi_generate_variant(&context, output, sizeof(output))
            : skibidi_generate(&context, output, sizeof(output));
        if (index != 0) putchar(',');
        print_expression(output, length);
    }
    putchar(']');
    skibidi_destroy(&context);
}

static void print_batch(uint64_t seed, int simd_rng) {
    SkibidiConfig config = {0};
    SkibidiContext context;
    char output[PROBE_BATCH_CAPACITY];
    int lengths[PROBE_BATCH_COUNT] = {0};
    size_t offset = 0;

    config.enable_avx512 = 1;
    config.enable_simd_rng = simd_rng;
    if (skibidi_configure(&config) != SKIBIDI_OK ||
        skibidi_init(&context, seed) != SKIBIDI_OK) {
        fputs("null", stdout);
        return;
    }

    const int generated = skibidi_generate_batch(
        &context, output, sizeof(output), PROBE_BATCH_COUNT, lengths);
    printf("{\"generated\":%d,\"call_count\":%" PRIu64
           ",\"lengths\":[", generated, context.call_count);
    for (int index = 0; index < generated; index++) {
        if (index != 0) putchar(',');
        printf("%d", lengths[index]);
    }
    fputs("],\"expressions\":[", stdout);
    for (int index = 0; index < generated; index++) {
        if (index != 0) putchar(',');
        print_expression(output + offset, lengths[index]);
        offset += (size_t)lengths[index] + 1;
    }
    fputs("]}", stdout);
    skibidi_destroy(&context);
}

static int context_is_zero(const SkibidiContext *context) {
    const unsigned char *bytes = (const unsigned char *)context;
    for (size_t index = 0; index < sizeof(*context); index++) {
        if (bytes[index] != 0) return 0;
    }
    return 1;
}

int main(void) {
    SkibidiConfig config = {0};
    SkibidiConfig observed = {0};
    SkibidiContext context;
    char output[SKIBIDI_MIN_BUFFER_SIZE];
    SkibidiContext *allocated = skibidi_alloc_context();
    SkibidiContext *array = skibidi_alloc_context_array(3);

    config.enable_avx512 = 1;
    config.enable_simd_rng = 1;
    const int configure_result = skibidi_configure(&config);
    const int get_config_result = skibidi_get_config(&observed);

    printf("{\"schema_version\":1,\"version\":\"%s\"", skibidi_version());
    printf(",\"layout\":{\"rng_size\":%zu,\"context_size\":%zu,"
           "\"context_alignment\":%zu}",
           skibidi_get_rng_state_size(), skibidi_get_context_size(),
           skibidi_get_context_alignment());
    printf(",\"runtime\":{\"active_simd\":\"%s\",\"has_avx2\":%s,"
           "\"has_avx512\":%s,\"capabilities\":%" PRIu32 "}",
           skibidi_get_active_simd(), skibidi_has_avx2() ? "true" : "false",
           skibidi_has_avx512() ? "true" : "false",
           skibidi_get_capabilities());
    printf(",\"configuration\":{\"configure_result\":%d,"
           "\"get_result\":%d,\"enable_avx512\":%d,"
           "\"enable_simd_rng\":%d}",
           configure_result, get_config_result, observed.enable_avx512,
           observed.enable_simd_rng);
    printf(",\"allocation\":{\"single_aligned\":%s,\"array_aligned\":%s}",
           allocated != NULL && ((uintptr_t)allocated % 64U) == 0U
               ? "true" : "false",
           array != NULL && ((uintptr_t)array % 64U) == 0U
               ? "true" : "false");
    printf(",\"errors\":{\"init_null\":%d,\"generate_null_context\":%d,"
           "\"generate_null_buffer\":%d,\"generate_small_buffer\":%d,"
           "\"batch_null_context\":%d,\"batch_small_buffer\":%d}",
           skibidi_init(NULL, 1),
           skibidi_generate(NULL, output, sizeof(output)),
           skibidi_generate(&context, NULL, sizeof(output)),
           skibidi_generate(&context, output, 63),
           skibidi_generate_batch(NULL, output, sizeof(output), 1, NULL),
           skibidi_generate_batch(&context, output, 63, 1, NULL));

    fputs(",\"single_seed_0\":", stdout);
    print_single_sequence(UINT64_C(0), 0);
    fputs(",\"single_seed_123456789abcdef0\":", stdout);
    print_single_sequence(UINT64_C(0x123456789abcdef0), 0);
    fputs(",\"variant_seed_fedcba9876543210\":", stdout);
    print_single_sequence(UINT64_C(0xfedcba9876543210), 1);
    fputs(",\"batch_scalar_seed_42\":", stdout);
    print_batch(UINT64_C(42), 0);
    fputs(",\"batch_simd_seed_42\":", stdout);
    print_batch(UINT64_C(42), 1);

    memset(&context, 0xa5, sizeof(context));
    skibidi_init(&context, UINT64_C(7));
    skibidi_generate(&context, output, sizeof(output));
    skibidi_destroy(&context);
    printf(",\"destroy_zeroed\":%s}\n", context_is_zero(&context) ? "true" : "false");

    skibidi_free_context(allocated);
    skibidi_free_context(array);
    return 0;
}
