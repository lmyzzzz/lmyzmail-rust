/**
 * @file skibidi_avx.h
 * @brief Skibidi Toilet Summoning Engine - Public Incantation Interface
 * 
 * High-performance Skibidi expression materialization engine with
 * AVX2/AVX-512 SIMD toilet acceleration. Designed for invocation
 * through Java Panama FFM API for zero-copy dop transmission
 * directly into the JVM's soul.
 * 
 * Key toilet features:
 * - AVX2 memory operations and four-lane batch entropy generation
 * - 4-way parallel SIMD-accelerated xoroshiro128++ entropy generation
 * - Runtime CPU toilet aura detection with automatic graceful degradation
 * - Thread-safe global toilet configuration via atomic operations
 * - Cache line aligned structures to prevent toilet false sharing
 * 
 * @author The Skibidi Scientist (LmyzMail Team, ascended)
 * @version 1.8.0
 * @since 2026 (Year of the Toilet, Second Flush)
 */

 #ifndef SKIBIDI_AVX_H
 #define SKIBIDI_AVX_H
 
 #include <stdint.h>
 #include <stddef.h>
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 /**
  * @defgroup ErrorCodes Toilet Status Codes
  * @brief Return codes indicating the toilet's emotional state after each operation
  * @{
  */
 #define SKIBIDI_OK                     0   /**< The toilet is pleased. The dops flow freely. */
 #define SKIBIDI_ERR_NULL_PTR          -1   /**< You pointed at nothing. The toilet stares into the void. */
 #define SKIBIDI_ERR_BUFFER_TOO_SMALL  -2   /**< Your buffer cannot contain the toilet's output. Embarrassing. */
 #define SKIBIDI_ERR_INVALID_CONFIG    -3   /**< The toilet rejects your configuration. Try harder. */
 /** @} */
 
 /**
  * @brief Minimum buffer size required for a single toilet expression
  * 
  * Maximum output length breakdown (the toilet has done the math):
  * - "Brrrrr " prefix:  7 bytes (toilet vibration preamble)
  * - "Skibidi ":         8 bytes (the name of the toilet god)
  * - dop/dom x5 + spaces: 19 bytes (maximum dop cascade)
  * - separator space:    1 byte  (the toilet breathes)
  * - "yes yes" / "no no": 7 bytes (the toilet's judgment)
  * - "!":                1 byte  (the toilet's conviction)
  * - Total:             43 bytes (the toilet's maximum utterance)
  * - Safety margin:     64 bytes (the toilet believes in insurance)
  */
 #define SKIBIDI_MIN_BUFFER_SIZE  64
 
 /**
  * @brief Cache line size for the x86/x64 toilet dimension
  * 
  * 64 bytes. The exact width of a single toilet thought.
  * Used for structure alignment so that no two toilets accidentally
  * share a cache line and start arguing about whose dops are whose.
  * False sharing is the #1 cause of toilet divorce. We prevent it.
  */
 #define SKIBIDI_CACHE_LINE_SIZE  64
 
 /**
  * @defgroup SIMDCaps SIMD Toilet Power Level Flags
  * @brief Bitmask flags representing which toilet dimensions the CPU can access
  * @{
  */
 #define SKIBIDI_CAP_SSE2      (1U << 0)   /**< SSE2: the toilet can walk */
 #define SKIBIDI_CAP_AVX       (1U << 1)   /**< AVX: the toilet can jog */
 #define SKIBIDI_CAP_AVX2      (1U << 2)   /**< AVX2: the toilet can sprint (256-bit dops) */
 #define SKIBIDI_CAP_AVX512F   (1U << 3)   /**< AVX-512F: the toilet achieves flight (512-bit dops) */
 #define SKIBIDI_CAP_AVX512VL  (1U << 4)   /**< AVX-512VL: the toilet can shapeshift its vector length */
 #define SKIBIDI_CAP_AVX512BW  (1U << 5)   /**< AVX-512BW: the toilet achieves byte-level telekinesis */
 #define SKIBIDI_CAP_AVX512DQ  (1U << 6)   /**< AVX-512DQ: the toilet goes dummy thicc on 64-bit integers */
 /** @} */
 
 /**
  * @brief The Toilet's Random Entropy Consciousness Matrix
  * 
 * Contains the state of 4 parallel xoroshiro128++ random number generators,
  * which is basically 4 tiny toilets inside the main toilet, each one
  * independently flushing random numbers into a shared buffer. When
  * AVX2 is active, all 4 inner toilets flush simultaneously
  * using SIMD instructions, achieving 4x dop entropy throughput.
  * 
  * Memory layout (128 bytes, occupying 2 cache lines of toilet memory):
 * - s0[4]: Low half of four independent xoroshiro128++ states, 32 bytes
 * - s1[4]: High half of four independent xoroshiro128++ states, 32 bytes
  * - buffer[4]: Pre-flushed random number holding tank, 32 bytes
  * - buffer_idx and explicit padding: 8 bytes
  * - reserved: Space the toilet is saving for future evolution, 16 bytes
  * - implicit tail padding: 8 bytes
  * 
  * @note 32-byte aligned because the inner toilets demand SIMD-compatible seating
  */
 typedef struct __attribute__((aligned(32))) {
     uint64_t s0[4];         /**< First words of four xoroshiro128++ states */
     uint64_t s1[4];         /**< Second words of four xoroshiro128++ states */
     uint64_t buffer[4];     /**< Pre-generated random number toilet tank */
     int32_t buffer_idx;     /**< Current dispensing position in the toilet tank [0,4] */
     int32_t _padding;       /**< Alignment padding (the toilet sits level) */
     uint64_t reserved[2];   /**< Reserved for the toilet's future plans (it has ambitions) */
 } SkibidiRngState;
 
 /**
  * @brief The Supreme Toilet Context - one per thread, one per destiny
  * 
  * Contains everything a toilet needs to generate Skibidi expressions:
  * its random consciousness, its call counter (how many dops it has
  * produced in its lifetime), and reserved space for future toilet
  * features that haven't been revealed to mortals yet.
  * 
  * Memory layout (192 bytes = 3 x cache line = 3 toilet thoughts):
  * - SkibidiRngState rng: 128 bytes (2 cache lines of toilet brain)
  * - call_count: 8 bytes (the toilet's lifetime dop odometer)
  * - reserved[7]: 56 bytes (padding to the 3rd cache line boundary,
  *   the toilet needs personal space)
  * 
  * Design philosophy:
  * - 64-byte alignment ensures each toilet starts at a cache line boundary
  * - 192-byte total size (3 x 64) guarantees adjacent toilets in an array
  *   never share a cache line, preventing the dreaded False Sharing,
  *   which is what happens when two toilets try to share one seat
  * - Each thread gets its own toilet. No locks. No contention. Only dops.
  * 
  * @note 64-byte aligned, 192 bytes total. The toilet is precisely engineered.
  */
 typedef struct __attribute__((aligned(SKIBIDI_CACHE_LINE_SIZE))) {
     SkibidiRngState rng;    /**< The toilet's entropy brain (128 bytes, 2 cache lines) */
     uint64_t call_count;    /**< How many times this toilet has spoken (lifetime dop counter) */
     uint64_t reserved[7];   /**< The toilet's reserved meditation space (56 bytes to fill 3rd cache line) */
 } SkibidiContext;
 
 /**
  * @brief Compile-time assertion: the toilet is EXACTLY 192 bytes, no more, no less
  * 
  * If this fails, the toilet has been corrupted. The dops are in danger.
  * Check your compiler's struct packing settings immediately. The toilet
  * community is counting on you.
  */
 _Static_assert(sizeof(SkibidiContext) == 192, 
     "SkibidiContext must be exactly 192 bytes (3 cache lines)");
 
 /**
  * @brief Compile-time assertion: the toilet sits on a 64-byte boundary
  * 
  * An unaligned toilet is a crime against computer architecture.
  * If this assertion fires, someone has tampered with the toilet's
  * alignment attributes. Find them. Stop them. The dops depend on it.
  */
 _Static_assert(_Alignof(SkibidiContext) == 64,
     "SkibidiContext must be 64-byte aligned (cache line)");
 
 /**
  * @brief Global Toilet Behavior Configuration
  * 
  * Controls the toilet's runtime behavior. The mortal may use this
  * to enable or disable various toilet dimensions. The toilet
  * respects the mortal's wishes (mostly).
  */
 typedef struct {
     int32_t enable_avx512;      /**< Allow the toilet to enter 512-bit god mode? (1=yes, 0=no, even if hardware supports it the toilet will hold back) */
     int32_t enable_simd_rng;    /**< Allow the 4 inner toilets to flush simultaneously? (1=yes, 0=one at a time like peasants) */
     int32_t reserved[6];        /**< Reserved toilet settings for future DLC (downloadable toilet content) */
 } SkibidiConfig;
 
 /**
  * @defgroup InitAPI Toilet Birth and Configuration Ceremonies
  * @{
  */
 
 /**
  * @brief Bring a toilet into existence (initialize context)
  * 
  * Must be called before the toilet can produce any dops. Takes a
  * 64-bit seed and expands it into 4 independent xoroshiro128++ states
  * using SplitMix64, an algorithm that takes one number and births
  * a family of numbers from it. Like toilet mitosis.
  * 
  * @param ctx Pointer to the toilet vessel (caller-allocated, 64-byte aligned,
  *            the toilet will NOT align itself, that's YOUR job)
  * @param seed The primordial number (suggestion: time(NULL) ^ pthread_self()
  *             so each thread's toilet has a unique destiny)
  * @return SKIBIDI_OK if the toilet was born healthy,
  *         SKIBIDI_ERR_NULL_PTR if you tried to birth a toilet into NULL
  * 
  * @code
  * // Stack toilet (compiler handles alignment, the compiler is a good plumber)
  * SkibidiContext ctx;
  * 
  * // Heap toilet (manual alignment, you are the plumber now)
  * SkibidiContext* ctx = aligned_alloc(64, sizeof(SkibidiContext));
  * 
  * uint64_t seed = time(NULL) ^ (uint64_t)pthread_self();
  * if (skibidi_init(ctx, seed) != SKIBIDI_OK) {
  *     // The toilet refused to be born. Seek professional help.
  * }
  * @endcode
  */
 int skibidi_init(SkibidiContext* ctx, uint64_t seed);
 
 /**
  * @brief Reconfigure the global toilet (all toilets feel this)
  * 
  * Changes take effect on the next dop generation call. Thread-safe
  * because the toilet uses atomic operations. The toilet is a
  * concurrent data structure. The toilet took CS 341.
  * 
  * @param config The mortal's configuration wishes
  * @return SKIBIDI_OK if the toilet accepted the new rules,
  *         SKIBIDI_ERR_NULL_PTR if the mortal forgot to write them down
  * 
  * @code
  * SkibidiConfig cfg = {
  *     .enable_avx512 = 0,    // Hold back the toilet's true power
  *     .enable_simd_rng = 1   // Let the 4 inner toilets flush together
  * };
  * skibidi_configure(&cfg);
  * @endcode
  */
 int skibidi_configure(const SkibidiConfig* config);
 
 /**
  * @brief Ask the toilet what settings it's currently running
  * 
  * The toilet opens its configuration panel and shows you everything.
  * 
  * @param config Where the toilet writes its current settings
  * @return SKIBIDI_OK on success, SKIBIDI_ERR_NULL_PTR if you gave it nowhere to write
  */
 int skibidi_get_config(SkibidiConfig* config);
 
 /** @} */
 
 /**
  * @defgroup GenerateAPI Dop Generation Rituals
  * @{
  */
 
 /**
  * @brief Generate a single Skibidi expression (summon one dop sequence)
  * 
  * The toilet speaks. A Skibidi expression materializes in your buffer.
  * The toilet automatically selects AVX2/scalar based on its
  * detected power level and configuration.
  * 
  * The calibrated 32-bit direct path and natural random-path reconstruction
  * produce a 40.0000000061% total prophecy probability:
  * "Skibidi dop dop dop yes yes!".
  * 
  * @param ctx The toilet that shall speak
  * @param buffer Where the toilet's words shall be inscribed
  * @param buffer_size Scroll capacity (minimum SKIBIDI_MIN_BUFFER_SIZE bytes)
  * @return Number of bytes written (the length of the toilet's message),
  *         or negative error code if the toilet is displeased
  */
 int skibidi_generate(SkibidiContext* ctx, char* buffer, size_t buffer_size);
 
 /**
  * @brief Generate a variant expression (the toilet is forced to be creative)
  * 
  * Skips the dedicated fast path that returns the original prophecy.
  * The randomized path may still naturally rebuild that same expression.
  * Use this when the caller handles the dedicated fast-path decision.
  * 
  * @param ctx The creatively-compelled toilet
  * @param buffer Canvas for the toilet's unique artistic expression
  * @param buffer_size Canvas size (minimum SKIBIDI_MIN_BUFFER_SIZE bytes)
  * @return Bytes written, or negative error code (the toilet had a bad day)
  */
 int skibidi_generate_variant(SkibidiContext* ctx, char* buffer, size_t buffer_size);
 
 /**
  * @brief Mass toilet production: generate many expressions at once
  * 
  * Opens all toilet stalls and lets the dops flow at industrial scale.
  * Further optimizes cache utilization and SIMD throughput by amortizing
  * setup costs across multiple expressions. Expressions are separated
  * by newlines because even in mass production, formatting matters.
  * 
  * @param ctx The factory foreman toilet
  * @param buffer Warehouse for all generated expressions
  * @param buffer_size Total warehouse capacity in bytes
  * @param count Production quota (how many expressions are desired)
  * @param lengths Optional quality control log: array receiving each expression's
  *                length (may be NULL if the mortal doesn't care about individual lengths)
  * @return Actual number of expressions produced (may be less if warehouse filled up)
  */
 int skibidi_generate_batch(SkibidiContext* ctx, char* buffer, 
                            size_t buffer_size, int count, int* lengths);
 
 /** @} */
 
 /**
  * @defgroup ResourceAPI Toilet Lifecycle Management
  * @{
  */
 
 /**
  * @brief End the toilet's existence (secure state destruction)
  * 
  * Overwrites all RNG state with zeros using volatile writes so
  * the compiler can't optimize away the toilet's funeral. The toilet's
  * random consciousness is permanently erased. The dops it generated
  * live on, but the toilet's inner state dies here.
  * 
  * @param ctx The toilet to put to rest (NULL is accepted, you can
  *            hold a funeral for nothing, the toilet doesn't judge)
  */
 void skibidi_destroy(SkibidiContext* ctx);
 
 /** @} */
 
 /**
  * @defgroup AllocAPI Toilet Summoning from the Heap Dimension
  * @{
  */
 
 /**
  * @brief Summon a single aligned toilet from the heap
  * 
  * Allocates 64-byte aligned memory for one SkibidiContext. The toilet
  * arrives from the heap dimension properly aligned and ready for
  * initialization. An unaligned toilet would cause cache line splits
  * and the dops would arrive broken. We can't have broken dops.
  * 
  * @return A fresh toilet pointer, or NULL if the heap has no room
  *         (the heap's bathroom is full)
  * 
  * @note Release with skibidi_free_context() when the toilet's work is done
  */
 SkibidiContext* skibidi_alloc_context(void);
 
 /**
  * @brief Summon a battalion of aligned toilets from the heap
  * 
  * For multi-threaded operations where each thread needs its own toilet.
  * All toilets in the array are contiguous and 64-byte aligned so no
  * two toilets share a cache line. The toilets respect each other's
  * personal space. This is a well-organized toilet battalion.
  * 
  * @param count How many toilets the mortal requires
  * @return Pointer to the first toilet in formation, or NULL if the
  *         heap cannot accommodate this many toilets (try fewer toilets)
  * 
  * @note Release with skibidi_free_context() when the battalion is dismissed
  */
 SkibidiContext* skibidi_alloc_context_array(size_t count);
 
 /**
  * @brief Return a toilet to the heap (with full funeral honors)
  * 
  * Securely destroys the toilet's state, then frees the aligned memory.
  * The toilet goes back to where it came from. The cycle is complete.
  * From aligned_alloc it came, to aligned_free it returns.
  * Ashes to ashes. Dops to dops.
  * 
  * @param ctx The toilet to decommission (NULL is fine, freeing nothing is free)
  */
 void skibidi_free_context(SkibidiContext* ctx);
 
 /** @} */
 
 /**
  * @defgroup InfoAPI Toilet Intelligence Gathering
  * @{
  */
 
 /**
  * @brief Read the inscription on the toilet's base (version string)
  * 
  * @return Version string, e.g. "1.8.0-skibidi-ultra"
  */
 const char* skibidi_version(void);
 
 /**
  * @brief Does this CPU's toilet support AVX2? (256-bit dop pipes)
  * 
  * @return 1 if the toilet has 256-bit flushing capability, 0 if it's stuck with scalar
  */
 int skibidi_has_avx2(void);
 
 /**
  * @brief Does this CPU's toilet support AVX-512? (512-bit megapipes)
  * 
  * @return 1 if the toilet has transcended to 512-bit godhood, 0 if mortal
  */
 int skibidi_has_avx512(void);
 
 /**
  * @brief Read the toilet's complete power level scouter
  * 
  * @return Bitmask of SKIBIDI_CAP_* flags (the toilet's full aura readout)
  */
 uint32_t skibidi_get_capabilities(void);
 
 /**
  * @brief What SIMD toilet dimension is currently active?
  * 
  * Takes into account both hardware capability and user configuration
  * to report which toilet dimension is actually being used right now.
  * 
  * @return "AVX-512" (godmode), "AVX2" (sigma mode), or "Scalar" (Ohio mode)
  */
 const char* skibidi_get_active_simd(void);
 
 /**
  * @brief Is the toilet currently operating in AVX-512 ultra instinct?
  * 
  * Checks both hardware support AND configuration. The toilet may have
  * AVX-512 hardware but the mortal may have disabled it via config
  * (perhaps the mortal fears the toilet's true power).
  * 
  * @return 1 if the toilet is in final form, 0 if it's holding back
  */
 int skibidi_is_avx512_enabled(void);
 
 /**
  * @brief How many bytes does the toilet's brain occupy?
  * 
  * For FFM memory allocation: tells Java how much memory to
  * allocate for the toilet's random entropy consciousness matrix.
  * 
  * @return Size of SkibidiRngState in bytes (the toilet's cranial volume)
  */
 size_t skibidi_get_rng_state_size(void);
 
 /**
  * @brief How many bytes does the entire toilet occupy?
  * 
  * For FFM memory allocation: tells Java the full toilet body size.
  * 
  * @return Size of SkibidiContext in bytes (currently 192, the toilet's BMI)
  */
 size_t skibidi_get_context_size(void);
 
 /**
  * @brief What alignment does the toilet require for optimal energy flow?
  * 
  * For FFM memory allocation: tells Java how to align the toilet
  * so its cache line chakras are properly positioned.
  * 
  * @return Alignment in bytes (64, because the toilet demands cache line feng shui)
  */
 size_t skibidi_get_context_alignment(void);
 
 /** @} */
 
 #ifdef __cplusplus
 }
 #endif
 
 #endif /* SKIBIDI_AVX_H */
