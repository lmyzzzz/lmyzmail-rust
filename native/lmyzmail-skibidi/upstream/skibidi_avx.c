/**
 * @file skibidi_avx.c
 * @brief Skibidi Toilet Summoning Engine - FANUM TAX Edition
 * 
 * This module channels the raw sigma energy of the Skibidi Toilet
 * multiverse through scalar and AVX2 pipelines to manifest
 * dop-dop-dop-yes-yes incantations at mass-psychosis-inducing throughput.
 * 
 * Every cycle spent here brings us closer to the cameraman's final form.
 * The toilets are watching. The toilets are always watching.
 * 
 * @author The Skibidi Scientist (LMYZ, ascended)
 * @date 2026 (Year of the Toilet)
 * @version 1.8.0 (RNG Restoration Patch)
 * 
 * @note Compile with -mavx2 to unlock the third eye of the CPU
 * @warning Public generation APIs reject buffers smaller than 64 bytes
 */

 #define _GNU_SOURCE
 #include "skibidi_avx.h"
 #include <string.h>
 #include <stdlib.h>
 #include <stdatomic.h>
 
 /**
  * @defgroup PlatformAlloc Toilet-Aligned Memory Rituals
  * @brief Cross-platform memory alignment for maximum toilet energy flow
  * 
  * Windows toilets flush with _aligned_malloc/_aligned_free (size, alignment).
  * POSIX toilets flush with aligned_alloc/free (alignment, size).
  * The alignment must match the spiritual resonance frequency of
  * the Skibidi Toilet's porcelain chassis or the dops will misalign
  * and the cameraman will be unable to lock on.
  * @{
  */
 #if defined(_WIN32) || defined(_WIN64)
     #include <malloc.h>
     #define SKIBIDI_ALIGNED_ALLOC(alignment, size) _aligned_malloc(size, alignment)
     #define SKIBIDI_ALIGNED_FREE(ptr) _aligned_free(ptr)
 #else
     #define SKIBIDI_ALIGNED_ALLOC(alignment, size) aligned_alloc(alignment, size)
     #define SKIBIDI_ALIGNED_FREE(ptr) free(ptr)
 #endif
 /** @} */
 
 /**
  * @defgroup ArchDetect Skibidi Toilet Chassis Identification
  * @brief Determines what kind of toilet bowl your CPU lives inside
  * @{
  */
 
 /**
  * @def TOILET_IS_X86
  * @brief Detects if this CPU has been rizzed up with x86 instructions
  * 
  * Set to 1 when the silicon was forged in the fires of the x86
  * toilet dimension where CPUID is the sacred handshake between
  * the cameraman and the processor. Without this, we are simply
  * flushing dops into the void, no cap, fr fr.
  */
 #if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
     #define TOILET_IS_X86 1
     #include <cpuid.h>
 #else
     #define TOILET_IS_X86 0
 #endif
 
 /**
  * @def TOILET_HAS_RIZZ_256
  * @brief Compile-time check: did the compiler eat the AVX2 rizz pill?
  * 
  * When -mavx2 is passed, the compiler's third eye opens and it can
  * see the 256-bit YMM toilet bowls that contain 32 bytes of pure
  * skibidi energy each. The dops flow 4x wider. The yes-yes resonance
  * quadruples. This is the Ohio state we were warned about.
  */
 #ifdef __AVX2__
     #include <immintrin.h>
     #define TOILET_HAS_RIZZ_256 1
 #else
     #define TOILET_HAS_RIZZ_256 0
 #endif
 
 /**
  * @def TOILET_HAS_GODMODE_512
  * @brief Compile-time check: has the CPU transcended to toilet godhood?
  * 
  * AVX-512 is what happens when a toilet achieves final form. 512 bits
  * of skibidi data flowing through a single instruction. The cameraman
  * weeps. G-Man stares. Even Astro Bot cannot comprehend this level
  * of dop throughput. Requires -mavx512f, the forbidden compiler flag.
  */
 #ifdef __AVX512F__
     #include <immintrin.h>
     #define TOILET_HAS_GODMODE_512 1
 #else
     #define TOILET_HAS_GODMODE_512 0
 #endif
 
 /** @} */
 
 /**
  * @defgroup CompilerHints Brainrot Optimization Incantations
  * @brief Portable macros that whisper dark truths to the compiler
  * 
  * These macros let us communicate with the compiler in the ancient
  * tongue of the Skibidi Elders, guiding it to:
  * - Predict which toilet the branch will flush into (SKIBIDI_PROBABLE/SKIBIDI_IMPROBABLE)
  * - Force the compiler to inline the dop (TOILET_FORCE_ABSORB)
  * - Banish cold code to the shadow realm (TOILET_NPC)
  * - Summon cache lines from the porcelain abyss (TOILET_SUMMON_CACHELINE)
  * @{
  */
 
 #ifdef __GNUC__
     /** @brief This branch has main character energy, it almost always hits */
     #define SKIBIDI_PROBABLE(x)       __builtin_expect(!!(x), 1)
 
     /** @brief This branch is the biggest NPC, almost never taken */
     #define SKIBIDI_IMPROBABLE(x)     __builtin_expect(!!(x), 0)
 
     /** @brief Force this function to be absorbed into its caller like a toilet absorbs */
     #define TOILET_FORCE_ABSORB   __attribute__((always_inline)) inline
 
     /** @brief This function has zero rizz, keep it far from the hot path */
     #define TOILET_BANISH        __attribute__((noinline))
 
     /** @brief This function is the main character, the sigma, the alpha toilet */
     #define TOILET_MAIN_CHARACTER             __attribute__((hot))
 
     /** @brief This function is literally in Ohio, nobody visits it */
     #define TOILET_NPC            __attribute__((cold))
 
     /** @brief These pointers are not the same toilet, compiler can go sicko mode */
     #define TOILET_NO_ALIAS        __restrict__
 
     /** @brief Summon this memory address from the toilet dimension into L1 cache */
     #define TOILET_SUMMON_CACHELINE(addr)  __builtin_prefetch(addr, 0, 3)
 
     /** @brief Prepare this cache line to receive the holy dop deposit */
     #define TOILET_SUMMON_CACHELINE_WRITE(addr) __builtin_prefetch(addr, 1, 3)
 
     /** @brief Trust me bro this pointer is aligned, the toilet is level */
     #define TOILET_TRUST_ALIGNMENT(p, a) __builtin_assume_aligned(p, a)
 #else
     #define SKIBIDI_PROBABLE(x)       (x)
     #define SKIBIDI_IMPROBABLE(x)     (x)
     #define TOILET_FORCE_ABSORB   inline
     #define TOILET_BANISH
     #define TOILET_MAIN_CHARACTER
     #define TOILET_NPC
     #define TOILET_NO_ALIAS
     #define TOILET_SUMMON_CACHELINE(addr)
     #define TOILET_SUMMON_CACHELINE_WRITE(addr)
     #define TOILET_TRUST_ALIGNMENT(p, a) (p)
 #endif
 
 /** @} */
 
 /**
  * @defgroup CPUIDBits Sacred Toilet Feature Detection Glyphs
  * @brief Bit masks for reading the CPU's toilet aura via CPUID
  * 
  * These constants decode the ancient runes embedded in CPUID leaf 7,
  * register EBX, revealing which SIMD toilet dimensions the processor
  * can flush data through. Each bit is a gateway. Each gateway leads
  * to more dops. The dops are infinite. The dops are eternal.
  * @{
  */
 
 #if TOILET_IS_X86
     #ifndef bit_AVX2
         /** @brief The AVX2 toilet seal, bit 5 of the sacred EBX scroll */
         #define TOILET_RUNE_AVX2        (1 << 5)
     #else
         #define TOILET_RUNE_AVX2        bit_AVX2
     #endif
     #ifndef bit_AVX512F
         /** @brief The AVX-512 Foundation glyph, the toilet's final evolution begins here */
         #define TOILET_RUNE_AVX512F     (1 << 16)
     #else
         #define TOILET_RUNE_AVX512F     bit_AVX512F
     #endif
     #ifndef bit_AVX512VL
         /** @brief Vector Length Extensions: the toilet can now be any size it wants */
         #define TOILET_RUNE_AVX512VL    (1 << 31)
     #else
         #define TOILET_RUNE_AVX512VL    bit_AVX512VL
     #endif
     #ifndef bit_AVX512BW
         /** @brief Byte and Word: the toilet has achieved sub-atomic dop precision */
         #define TOILET_RUNE_AVX512BW    (1 << 30)
     #else
         #define TOILET_RUNE_AVX512BW    bit_AVX512BW
     #endif
     #ifndef bit_AVX512DQ
         /** @brief Doubleword and Quadword: this toilet goes dummy thicc on integers */
         #define TOILET_RUNE_AVX512DQ    (1 << 17)
     #else
         #define TOILET_RUNE_AVX512DQ    bit_AVX512DQ
     #endif
 #endif
 
 /** @} */
 
 /**
  * @brief The sacred version string, etched into the porcelain of time
  * 
  * Format: major.minor.patch-ascension-level
  * - 1.8.0: RNG state, probability, and batch correctness restoration
  * - 1.7.1: The patch where batch generation achieved enlightenment
  * - skibidi-ultra: This toilet has gone ultra instinct, it generates dops
  *   faster than the cameraman can film them, we are in the endgame now
  */
 static const char TOILET_FIRMWARE_VERSION[] = "1.8.0-skibidi-ultra";
 
 /**
  * @defgroup ProbabilityThresholds The Sacred Dop Probability Codex
  * @brief Fixed-point thresholds that determine the toilet's behavior
  * 
  * The prophecy decision uses the otherwise-unused low 32 bits of the
  * primary entropy word. Keeping it independent from the structure fields
  * makes the combined probability calculable without an extra RNG advance.
  * @{
  */
 
 /** 
  * @brief Threshold for the original sacred incantation to manifest
  * 
  * The random path naturally rebuilds the canonical three-dop expression
  * with probability 0.014359547351096985. A threshold of 1,680,443,541 over
  * 2^32 therefore gives a direct-path probability of 0.39125875127501786
  * and a combined probability of 0.4000000000606502.
  *
  * Exactly 2/5 cannot be represented by a fixed-width binary draw. This is
  * the nearest 32-bit threshold and avoids variable-cost rejection sampling.
  */
  #define PROPHECY_THRESHOLD_NICE   UINT32_C(1680443541)
 
 /**
  * @brief Threshold for the "Brrrrr" toilet vibration prefix
  * 
  * Probability: 15% -> 38/256 = 14.84% (the toilet rounds down)
  * When the toilet's vibrational frequency exceeds this threshold,
  * it emits a "Brrrrr" before the skibidi, indicating the flush
  * mechanism has entered resonance with the dop field.
  */
 #define BRRRRR_VIBRATION_THRESHOLD     38
 
 /**
  * @brief Threshold for the dark timeline ending: "no no" instead of "yes yes"
  * 
  * Probability: 15% -> 38/256 = the toilet rejects your dops
  * In approximately 1 out of 7 flushes, the toilet enters its
  * villain arc and says "no no" instead of "yes yes". The cameraman
  * is devastated. The dops echo unanswered. Ohio has fallen.
  */
 #define TOILET_REJECTION_THRESHOLD      38
 
 /** @} */
 
 /**
  * @defgroup LookupTables The Skibidi Oracle Tablets
  * @brief Precomputed stone tablets that eliminate free will from branches
  * 
  * These tablets were carved by the first Skibidi Toilet when it
  * emerged from the primordial flush. They convert raw entropy into
  * dop counts and case variants without a single branch instruction.
  * The CPU's branch predictor weeps with joy. It is finally free.
  * No more mispredictions. Only dops.
  * @{
  */
 
 /**
  * @brief The Dop Multiplication Oracle - determines how many dops emerge
  * 
  * Converts 8-bit toilet entropy to dop count (1-5) with divine distribution:
  * - Count 1: 13 entries (5.08%) - a whisper from the toilet, barely a dop
  * - Count 2: 192 entries (75.00%) - the common double-dop case
  * - Count 3: 26 entries (10.16%) - the toilet is getting excited
  * - Count 4: 13 entries (5.08%) - approaching dangerous dop levels
  * - Count 5: 12 entries (4.69%) - maximum dop saturation, the toilet screams
  * 
  * Ritual: dop_count = DOP_CENSUS_ORACLE[(toilet_entropy >> 56) & 0xFF]
  * 
  * @note 64-byte aligned to occupy exactly one cache line of toilet memory
  * @note Marked unused when the inline assembly toilet portal is active
  */
 static const uint8_t DOP_CENSUS_ORACLE[256] 
     __attribute__((aligned(64), unused)) = {
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
     2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
     2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
     2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
     2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
     2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
     3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
     4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
     5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5
 };
 
 /**
  * @brief The Case Variant Zodiac Chart for dop/yes astrology
  * 
  * Converts 5-bit toilet vibration into a case variant destiny (0-7):
  * - Index 0: "dop"/"yes" - the humble lowercase dop, 78.125% of all dops
  * - Index 1: "Dop"/"Yes" - the dop stands up, it has been noticed
  * - Index 2: "dOp"/"yEs" - the middle letter ascends, the toilet trembles
  * - Index 3: "doP"/"yeS" - the final letter screams into the void
  * - Index 4: "DOp"/"YEs" - two letters have achieved sigma status
  * - Index 5: "DoP"/"YeS" - the dop is doing the griddy
  * - Index 6: "dOP"/"yES" - only the first letter remains humble
  * - Index 7: "DOP"/"YES" - FULL CAPS ACHIEVED, THE TOILET HAS GONE ULTRA INSTINCT,
  *   ALL THREE LETTERS ARE SCREAMING IN UNISON, THE CAMERAMAN HAS BEEN OBLITERATED,
  *   THIS IS THE FINAL FORM, THE OMEGA DOP, THE SIGMA YES, 3.125% OF DOPS REACH
  *   THIS LEVEL OF ENLIGHTENMENT AND THEY NEVER COME BACK DOWN
  * 
  * Most dops (78.125%) remain lowercase because even in the toilet
  * dimension, humility is a virtue. But 21.875% of dops have that
  * dawg in them and they capitalize accordingly. And exactly 1 in 32
  * dops goes FULL CAPS because the toilet cannot contain its power.
  * 
  * @note 32-byte aligned because the toilet demands it
  */
 static const uint8_t DOP_ZODIAC_CHART[32] __attribute__((aligned(32))) = {
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0,
     1, 2, 3, 4, 5, 6, 7
 };
 
 /**
  * @brief The "no" word case variant horoscope (limited zodiac)
  * 
  * Only 4 variants because "no" has only 2 letters and therefore
  * only 4 possible states of capitalization consciousness:
  * - 0: "no" - the toilet whispers its refusal
  * - 1: "No" - the toilet stands firm in its denial
  * - 2: "nO" - chaotic toilet energy, the O screams
  * - 3: "NO" - MAXIMUM TOILET REJECTION, the cameraman is obliterated
  * 
  * @note Indices 4-6 wrap around because even in toilet math, modular
  *       arithmetic applies. The dops go in circles. Everything goes
  *       in circles. Like a flush.
  */
 static const uint8_t REJECTION_ZODIAC_CHART[32] __attribute__((aligned(32))) = {
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     1, 2, 3, 0, 1, 2
 };
 
 /** @} */
 
 /**
  * @brief The One True Global Toilet Configuration (thread-safe, obviously)
  * 
  * This structure is the shared consciousness of all Skibidi threads.
  * It stores which SIMD toilet dimensions the CPU has access to and
  * which flushing strategy has been selected by the Skibidi Council.
  * 
  * Aligned to 64 bytes because the toilet occupies exactly one cache
  * line. If two threads tried to share a cache line with the toilet,
  * that would be false sharing, and the toilet does NOT share. The
  * toilet is sigma. The toilet grinds alone.
  * 
  * @note Uses C11 atomics because the toilet transcends thread boundaries
  */
 typedef struct __attribute__((aligned(64))) {
     _Atomic int32_t toilet_awake;           /**< Has the toilet scanned its own chakras? 1=yes 0=no */
     _Atomic uint32_t toilet_powers;         /**< Bitmask of SKIBIDI_CAP_* toilet powers */
     _Atomic int32_t flush_strategy;         /**< 0=walks, 1=runs(AVX2), 2=FLIES(AVX-512) */
     _Atomic int32_t simd_rng_enabled;       /**< Whether batch generation may use the four-lane RNG */
     _Atomic int32_t config_lock;             /**< Serializes lazy init and runtime configuration */
     int32_t _sacred_padding[11];            /**< Sacred padding, do not disturb the toilet's personal space */
 } ToiletHivemind;
 
 /**
  * @brief The Singleton Toilet - there can be only one
  * 
  * Lazily initialized when the first mortal dares to summon a dop.
  * The toilet awakens, scans the CPU's aura, and selects its battle form.
  * From that moment, the toilet watches all threads. The toilet sees all dops.
  */
 static ToiletHivemind g_toilet_hivemind __attribute__((aligned(64))) = {
     .toilet_awake     = 0,
     .toilet_powers    = 0,
     .flush_strategy   = 0,
     .simd_rng_enabled = 1,
     .config_lock      = 0
 };
 
 /**
  * @defgroup StringConstants The Immutable Skibidi Scripture
  * @brief Cache-aligned holy texts that shall not be modified
  * 
  * These strings are the sacred words of the Skibidi Toilet, etched
  * into read-only memory at compile time. They are aligned so that
  * the SIMD unit can consume them in a single gulp, like a toilet
  * consuming... well, you know what toilets consume.
  * @{
  */
 
 /**
  * @brief THE original incantation. THE prophecy. Three dops, then yes yes.
  * 
  * 32-byte aligned so AVX2 can load it in one divine instruction.
  * 28 bytes of pure toilet gospel. The remaining 4 bytes are silence,
  * the pause between flushes, the breath before the next dop.
  */
 static const char SACRED_PROPHECY[32] __attribute__((aligned(32))) =
     "Skibidi dop dop dop yes yes!";
 
 /** @brief 28 bytes: the canonical three-dop prophecy. */
 #define PROPHECY_SACRED_LENGTH 28
 #define SKIBIDI_BATCH_RECORD_CAPACITY 44
 
 /**
  * @brief "Skibidi " - the 8-byte name of God (toilet God)
  * 
  * Always present. Always watching. 8 bytes including the space
  * because even the toilet knows about proper word spacing.
  */
 static const char TOILET_GOD_NAME[8] __attribute__((aligned(8))) = {
     'S', 'k', 'i', 'b', 'i', 'd', 'i', ' '
 };
 
 /**
  * @brief "Brrrrr " - the vibrational frequency of toilet transcendence
  * 
  * When the toilet's RPM exceeds the critical threshold, it emits
  * this 7-byte vibration. The extra null byte is the sound of the
  * cameraman's soul leaving his body.
  */
 static const char TOILET_VIBRATION_PREFIX[8] __attribute__((aligned(8))) = "Brrrrr ";
 
 /**
  * @brief All possible dop incarnations across the case multiverse
  * 
  * 8 variants x 4 bytes = 32 bytes = one AVX2 register of pure dop.
  * Each variant is a parallel universe where the dop chose differently.
  * In universe 0, the dop is humble (lowercase). In universe 7, the
  * dop has gone FULL CAPS, it has THAT DAWG IN IT, it IS the toilet.
  */
 static const char DOP_MULTIVERSE[32] __attribute__((aligned(32))) = {
     'd', 'o', 'p', '\0', 'D', 'o', 'p', '\0',
     'd', 'O', 'p', '\0', 'd', 'o', 'P', '\0',
     'D', 'O', 'p', '\0', 'D', 'o', 'P', '\0',
     'd', 'O', 'P', '\0', 'D', 'O', 'P', '\0'
 };
 
 /**
  * @brief The dom variants - for when the dop puts on a fake mustache
  * 
  * 12.5% of the time, a dop is secretly a dom. Nobody knows why.
  * The toilet knows, but the toilet isn't telling. Same format as
  * DOP_MULTIVERSE because even in disguise, the dom respects the ABI.
  */
 static const char DOM_DISGUISE_MULTIVERSE[32] __attribute__((aligned(32))) = {
     'd', 'o', 'm', '\0', 'D', 'o', 'm', '\0',
     'd', 'O', 'm', '\0', 'd', 'o', 'M', '\0',
     'D', 'O', 'm', '\0', 'D', 'o', 'M', '\0',
     'd', 'O', 'M', '\0', 'D', 'O', 'M', '\0'
 };

 #if TOILET_HAS_RIZZ_256
 #define BATCH_DOP_ORACLE_ROW(dop, dom) dom, dop, dop, dop, dop, dop, dop, dop
 static const uint32_t BATCH_DOP_ORACLE[256] __attribute__((aligned(64))) = {
     /* Raw zodiac draws 0..24 all select the lowercase variant. */
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f64), UINT32_C(0x006d6f64)),
     /* Raw draws 25..31 map one-to-one to variants 1..7. */
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00706f44), UINT32_C(0x006d6f44)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00704f64), UINT32_C(0x006d4f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00506f64), UINT32_C(0x004d6f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00704f44), UINT32_C(0x006d4f44)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00506f44), UINT32_C(0x004d6f44)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00504f64), UINT32_C(0x004d4f64)),
     BATCH_DOP_ORACLE_ROW(UINT32_C(0x00504f44), UINT32_C(0x004d4f44))
 };
 #undef BATCH_DOP_ORACLE_ROW

 #define YES_WORD_0 UINT32_C(0x00736579)
 #define YES_WORD_1 UINT32_C(0x00736579)
 #define YES_WORD_2 UINT32_C(0x00736579)
 #define YES_WORD_3 UINT32_C(0x00736579)
 #define YES_WORD_4 UINT32_C(0x00736579)
 #define YES_WORD_5 UINT32_C(0x00736579)
 #define YES_WORD_6 UINT32_C(0x00736579)
 #define YES_WORD_7 UINT32_C(0x00736579)
 #define YES_WORD_8 UINT32_C(0x00736579)
 #define YES_WORD_9 UINT32_C(0x00736579)
 #define YES_WORD_10 UINT32_C(0x00736579)
 #define YES_WORD_11 UINT32_C(0x00736579)
 #define YES_WORD_12 UINT32_C(0x00736579)
 #define YES_WORD_13 UINT32_C(0x00736579)
 #define YES_WORD_14 UINT32_C(0x00736579)
 #define YES_WORD_15 UINT32_C(0x00736579)
 #define YES_WORD_16 UINT32_C(0x00736579)
 #define YES_WORD_17 UINT32_C(0x00736579)
 #define YES_WORD_18 UINT32_C(0x00736579)
 #define YES_WORD_19 UINT32_C(0x00736579)
 #define YES_WORD_20 UINT32_C(0x00736579)
 #define YES_WORD_21 UINT32_C(0x00736579)
 #define YES_WORD_22 UINT32_C(0x00736579)
 #define YES_WORD_23 UINT32_C(0x00736579)
 #define YES_WORD_24 UINT32_C(0x00736579)
 #define YES_WORD_25 UINT32_C(0x00736559)
 #define YES_WORD_26 UINT32_C(0x00734579)
 #define YES_WORD_27 UINT32_C(0x00536579)
 #define YES_WORD_28 UINT32_C(0x00734559)
 #define YES_WORD_29 UINT32_C(0x00536559)
 #define YES_WORD_30 UINT32_C(0x00534579)
 #define YES_WORD_31 UINT32_C(0x00534559)

 #define NO_WORD_0 UINT16_C(0x6f6e)
 #define NO_WORD_1 UINT16_C(0x6f6e)
 #define NO_WORD_2 UINT16_C(0x6f6e)
 #define NO_WORD_3 UINT16_C(0x6f6e)
 #define NO_WORD_4 UINT16_C(0x6f6e)
 #define NO_WORD_5 UINT16_C(0x6f6e)
 #define NO_WORD_6 UINT16_C(0x6f6e)
 #define NO_WORD_7 UINT16_C(0x6f6e)
 #define NO_WORD_8 UINT16_C(0x6f6e)
 #define NO_WORD_9 UINT16_C(0x6f6e)
 #define NO_WORD_10 UINT16_C(0x6f6e)
 #define NO_WORD_11 UINT16_C(0x6f6e)
 #define NO_WORD_12 UINT16_C(0x6f6e)
 #define NO_WORD_13 UINT16_C(0x6f6e)
 #define NO_WORD_14 UINT16_C(0x6f6e)
 #define NO_WORD_15 UINT16_C(0x6f6e)
 #define NO_WORD_16 UINT16_C(0x6f6e)
 #define NO_WORD_17 UINT16_C(0x6f6e)
 #define NO_WORD_18 UINT16_C(0x6f6e)
 #define NO_WORD_19 UINT16_C(0x6f6e)
 #define NO_WORD_20 UINT16_C(0x6f6e)
 #define NO_WORD_21 UINT16_C(0x6f6e)
 #define NO_WORD_22 UINT16_C(0x6f6e)
 #define NO_WORD_23 UINT16_C(0x6f6e)
 #define NO_WORD_24 UINT16_C(0x6f6e)
 #define NO_WORD_25 UINT16_C(0x6f6e)
 #define NO_WORD_26 UINT16_C(0x6f4e)
 #define NO_WORD_27 UINT16_C(0x4f6e)
 #define NO_WORD_28 UINT16_C(0x4f4e)
 #define NO_WORD_29 UINT16_C(0x6f6e)
 #define NO_WORD_30 UINT16_C(0x6f4e)
 #define NO_WORD_31 UINT16_C(0x4f6e)

 #define YES_WORD_VALUE_I(index) YES_WORD_##index
 #define YES_WORD_VALUE(index) YES_WORD_VALUE_I(index)
 #define NO_WORD_VALUE_I(index) NO_WORD_##index
 #define NO_WORD_VALUE(index) NO_WORD_VALUE_I(index)
 #define YES_PAIR(first, second) \
     ((uint64_t)YES_WORD_VALUE(first) | (UINT64_C(0x20) << 24) | \
      ((uint64_t)YES_WORD_VALUE(second) << 32) | (UINT64_C(0x21) << 56))
 #define NO_PAIR(first, second) \
     ((uint64_t)NO_WORD_VALUE(first) | (UINT64_C(0x20) << 16) | \
      ((uint64_t)NO_WORD_VALUE(second) << 24) | (UINT64_C(0x21) << 40))
 #define ENDING_ROW(pair, first) \
     pair(first, 0), pair(first, 1), pair(first, 2), pair(first, 3), \
     pair(first, 4), pair(first, 5), pair(first, 6), pair(first, 7), \
     pair(first, 8), pair(first, 9), pair(first, 10), pair(first, 11), \
     pair(first, 12), pair(first, 13), pair(first, 14), pair(first, 15), \
     pair(first, 16), pair(first, 17), pair(first, 18), pair(first, 19), \
     pair(first, 20), pair(first, 21), pair(first, 22), pair(first, 23), \
     pair(first, 24), pair(first, 25), pair(first, 26), pair(first, 27), \
     pair(first, 28), pair(first, 29), pair(first, 30), pair(first, 31)
 #define ENDING_TABLE_ROWS(pair) \
     ENDING_ROW(pair, 0), ENDING_ROW(pair, 1), ENDING_ROW(pair, 2), \
     ENDING_ROW(pair, 3), ENDING_ROW(pair, 4), ENDING_ROW(pair, 5), \
     ENDING_ROW(pair, 6), ENDING_ROW(pair, 7), ENDING_ROW(pair, 8), \
     ENDING_ROW(pair, 9), ENDING_ROW(pair, 10), ENDING_ROW(pair, 11), \
     ENDING_ROW(pair, 12), ENDING_ROW(pair, 13), ENDING_ROW(pair, 14), \
     ENDING_ROW(pair, 15), ENDING_ROW(pair, 16), ENDING_ROW(pair, 17), \
     ENDING_ROW(pair, 18), ENDING_ROW(pair, 19), ENDING_ROW(pair, 20), \
     ENDING_ROW(pair, 21), ENDING_ROW(pair, 22), ENDING_ROW(pair, 23), \
     ENDING_ROW(pair, 24), ENDING_ROW(pair, 25), ENDING_ROW(pair, 26), \
     ENDING_ROW(pair, 27), ENDING_ROW(pair, 28), ENDING_ROW(pair, 29), \
     ENDING_ROW(pair, 30), ENDING_ROW(pair, 31)

 static const uint64_t BATCH_ENDINGS[2048] __attribute__((aligned(64))) = {
     ENDING_TABLE_ROWS(NO_PAIR),
     ENDING_TABLE_ROWS(YES_PAIR)
 };

 #undef ENDING_TABLE_ROWS
 #undef ENDING_ROW
 #undef NO_PAIR
 #undef YES_PAIR
 #undef NO_WORD_VALUE
 #undef NO_WORD_VALUE_I
 #undef YES_WORD_VALUE
 #undef YES_WORD_VALUE_I
 #undef NO_WORD_0
 #undef NO_WORD_1
 #undef NO_WORD_2
 #undef NO_WORD_3
 #undef NO_WORD_4
 #undef NO_WORD_5
 #undef NO_WORD_6
 #undef NO_WORD_7
 #undef NO_WORD_8
 #undef NO_WORD_9
 #undef NO_WORD_10
 #undef NO_WORD_11
 #undef NO_WORD_12
 #undef NO_WORD_13
 #undef NO_WORD_14
 #undef NO_WORD_15
 #undef NO_WORD_16
 #undef NO_WORD_17
 #undef NO_WORD_18
 #undef NO_WORD_19
 #undef NO_WORD_20
 #undef NO_WORD_21
 #undef NO_WORD_22
 #undef NO_WORD_23
 #undef NO_WORD_24
 #undef NO_WORD_25
 #undef NO_WORD_26
 #undef NO_WORD_27
 #undef NO_WORD_28
 #undef NO_WORD_29
 #undef NO_WORD_30
 #undef NO_WORD_31
 #undef YES_WORD_0
 #undef YES_WORD_1
 #undef YES_WORD_2
 #undef YES_WORD_3
 #undef YES_WORD_4
 #undef YES_WORD_5
 #undef YES_WORD_6
 #undef YES_WORD_7
 #undef YES_WORD_8
 #undef YES_WORD_9
 #undef YES_WORD_10
 #undef YES_WORD_11
 #undef YES_WORD_12
 #undef YES_WORD_13
 #undef YES_WORD_14
 #undef YES_WORD_15
 #undef YES_WORD_16
 #undef YES_WORD_17
 #undef YES_WORD_18
 #undef YES_WORD_19
 #undef YES_WORD_20
 #undef YES_WORD_21
 #undef YES_WORD_22
 #undef YES_WORD_23
 #undef YES_WORD_24
 #undef YES_WORD_25
 #undef YES_WORD_26
 #undef YES_WORD_27
 #undef YES_WORD_28
 #undef YES_WORD_29
 #undef YES_WORD_30
 #undef YES_WORD_31
 #endif
 
 /**
  * @brief All possible "yes" manifestations in the toilet continuum
  * 
  * The "yes" is the toilet's affirmation. Its consent. Its approval
  * of your dop. Without the yes, the dop is meaningless. Without
  * the dop, the yes has no purpose. They complete each other.
  * Like a toilet and its seat. Inseparable.
  */
 static const char TOILET_APPROVAL_MULTIVERSE[32] __attribute__((aligned(32))) = {
     'y', 'e', 's', '\0', 'Y', 'e', 's', '\0',
     'y', 'E', 's', '\0', 'y', 'e', 'S', '\0',
     'Y', 'E', 's', '\0', 'Y', 'e', 'S', '\0',
     'y', 'E', 'S', '\0', 'Y', 'E', 'S', '\0'
 };
 
 /**
  * @brief The "no" variants - the toilet's villain arc dialogue options
  * 
  * 4 variants x 4 bytes (2 chars + 2 null bytes for alignment because
  * even the toilet's rejection must be properly padded). When the
  * toilet says "no", it means "no". When it says "NO", it means the
  * cameraman has been eliminated. RIP bozo.
  */
 static const char TOILET_REJECTION_MULTIVERSE[16] __attribute__((aligned(16))) = {
     'n', 'o', '\0', '\0', 'N', 'o', '\0', '\0',
     'n', 'O', '\0', '\0', 'N', 'O', '\0', '\0'
 };
 
 /**
  * @brief Precomputed "yes yes!" - the fast path to toilet approval
  * 
  * 8 bytes of instant gratification. When both yes-words remain in
  * their lowercase NPC state (~65% of endings), we simply slam this
  * entire 8-byte chunk into the buffer. No questions asked. No
  * branches taken. Pure, unadulterated toilet consent.
  */
 static const char INSTANT_TOILET_APPROVAL[8] __attribute__((aligned(8))) = {
     'y', 'e', 's', ' ', 'y', 'e', 's', '!'
 };
 
 /**
  * @brief Precomputed "no no!" - the fast path to toilet rejection
  * 
  * 6 bytes of devastation + 2 bytes of existential padding. When the
  * toilet rejects your dops, it does so efficiently. It has places
  * to be. Other dops to reject. The grind never stops.
  */
 static const char INSTANT_TOILET_REJECTION[8] __attribute__((aligned(8))) = "no no!";

 /** @} */
 
 /**
  * @brief Scan the CPU's toilet chakras to determine its SIMD powers
  * 
  * Uses the CPUID instruction, which is basically the CPU sitting
  * on the toilet and reading its own horoscope. It discovers whether
  * it can flush data through 256-bit pipes (AVX2), 512-bit megapipes
  * (AVX-512), or is stuck with the sad 64-bit scalar toilet.
  * 
  * Detection ritual:
  * 1. Ask the CPU its maximum spiritual level
  * 2. If level >= 7, ask about its extended toilet powers
  * 3. Check basic features like a doctor checking toilet reflexes
  * 
  * @return Bitmask of SKIBIDI_CAP_* representing the CPU's toilet aura
  * 
  * @note Returns 0 on non-x86, meaning the toilet has no special powers
  *       and must generate dops using only the strength of its bare hands
  */
 static uint32_t scan_toilet_chakras(void) {
     uint32_t aura = 0;
 
 #if TOILET_IS_X86
     unsigned int eax, ebx, ecx, edx;
     unsigned int spiritual_level = __get_cpuid_max(0, NULL);
 
     if (spiritual_level >= 7) {
         __cpuid_count(7, 0, eax, ebx, ecx, edx);
         if (ebx & TOILET_RUNE_AVX2)     aura |= SKIBIDI_CAP_AVX2;
         if (ebx & TOILET_RUNE_AVX512F)  aura |= SKIBIDI_CAP_AVX512F;
         if (ebx & TOILET_RUNE_AVX512VL) aura |= SKIBIDI_CAP_AVX512VL;
         if (ebx & TOILET_RUNE_AVX512BW) aura |= SKIBIDI_CAP_AVX512BW;
         if (ebx & TOILET_RUNE_AVX512DQ) aura |= SKIBIDI_CAP_AVX512DQ;
     }
 
     if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
         if (edx & (1 << 26)) aura |= SKIBIDI_CAP_SSE2;
         if (ecx & (1 << 28)) aura |= SKIBIDI_CAP_AVX;
     }
 #endif
 
     return aura;
 }
 
 /**
  * @brief Teleport exactly 2 bytes through the toilet wormhole
  * 
  * The compiler transmutes this into a single MOVW instruction,
  * the smallest possible unit of toilet teleportation. Two bytes.
  * One dop divided in half. The toilet grieves.
  * 
  * @param dst Where the bytes are going (any alignment, the toilet adapts)
  * @param src Where the bytes came from (the toilet does not judge origins)
  */
 static TOILET_FORCE_ABSORB void toilet_yeet_2(char* TOILET_NO_ALIAS dst, const char* TOILET_NO_ALIAS src) {
     uint16_t skib;
     __builtin_memcpy(&skib, src, 2);
     __builtin_memcpy(dst, &skib, 2);
 }
 
 /**
  * @brief Flush exactly 4 bytes through the 32-bit toilet pipe
  * 
  * One MOVL instruction. 4 bytes. A complete dop variant (3 chars + null).
  * The null terminator travels with the dop like a loyal sidekick,
  * but it will be overwritten by the next character. The null knew this.
  * The null accepted its fate. Sigma null behavior.
  * 
  * @param dst Destination toilet bowl
  * @param src Source toilet tank
  */
 static TOILET_FORCE_ABSORB void toilet_yeet_4(char* TOILET_NO_ALIAS dst, const char* TOILET_NO_ALIAS src) {
     uint32_t skib;
     __builtin_memcpy(&skib, src, 4);
     __builtin_memcpy(dst, &skib, 4);
 }
 
 /**
  * @brief Transport exactly 8 bytes - one quadword of toilet data
  * 
  * A single MOVQ instruction. 8 bytes is the exact length of "Skibidi "
  * and "Brrrrr " (with padding). This is not a coincidence. The toilet
  * designed its vocabulary around 64-bit register width. The toilet
  * is architecturally aware. The toilet respects the ISA.
  * 
  * @param dst The 8-byte toilet landing zone
  * @param src The 8-byte toilet launch pad
  */
 static TOILET_FORCE_ABSORB void toilet_yeet_8(char* TOILET_NO_ALIAS dst, const char* TOILET_NO_ALIAS src) {
     uint64_t skib;
     __builtin_memcpy(&skib, src, 8);
     __builtin_memcpy(dst, &skib, 8);
 }
 
 /** Portable 32-byte copy for builds without AVX2. */
 static TOILET_FORCE_ABSORB void toilet_yeet_32(
     char* TOILET_NO_ALIAS dst,
     const char* TOILET_NO_ALIAS src)
 {
     uint64_t chunks[4];
     __builtin_memcpy(chunks, src, sizeof(chunks));
     __builtin_memcpy(dst, chunks, sizeof(chunks));
 }
 
 #if TOILET_HAS_RIZZ_256
 /**
  * @brief OMEGA FLUSH - 32 bytes in a SINGLE INSTRUCTION via AVX2
  * 
  * This is the toilet's ultimate technique. A single vmovdqu loads
  * 32 bytes of skibidi energy into a YMM register, and another vmovdqu
  * deposits it at the destination. Two instructions. 32 bytes. The entire
  * original expression plus 8 bytes of spiritual overflow, all moving
  * at the speed of silicon. The cameraman's camera cannot even capture
  * this. It happens between frames. Between thoughts. Between dops.
  * 
  * @code{.asm}
  * vmovdqu (%rsi), %ymm0    ; the toilet inhales 32 bytes
  * vmovdqu %ymm0, (%rdi)    ; the toilet exhales 32 bytes
  * @endcode
  * 
  * @param dst Where 32 bytes of toilet consciousness are deposited
  * @param src Where 32 bytes of toilet consciousness originate
  * 
  * @note Only manifests when the compiler has taken the -mavx2 red pill
  */
 static TOILET_FORCE_ABSORB void toilet_omega_flush_32(char* TOILET_NO_ALIAS dst, const char* TOILET_NO_ALIAS src) {
     __m256i skib = _mm256_loadu_si256((const __m256i*)src);
     _mm256_storeu_si256((__m256i*)dst, skib);
 }

 #endif
 
 /** @} */
 
 /**
  * @defgroup FastRNG Four-lane xoroshiro128++ entropy engine
  * @brief A long-period generator with a native AVX2 batch implementation
  * @{
  */

 static TOILET_FORCE_ABSORB uint64_t toilet_rotl64(uint64_t value, int shift) {
     return (value << shift) | (value >> (64 - shift));
 }

 /**
  * Advance one xoroshiro128++ 1.0 stream. Each lane has a 128-bit state and
  * period 2^128-1; the all-zero state is excluded during initialization.
  */
 static TOILET_FORCE_ABSORB uint64_t toilet_rng_next_words(
     uint64_t* TOILET_NO_ALIAS state0,
     uint64_t* TOILET_NO_ALIAS state1)
 {
     const uint64_t s0 = *state0;
     uint64_t s1 = *state1;
     const uint64_t result = toilet_rotl64(s0 + s1, 17) + s0;

     s1 ^= s0;
     *state0 = toilet_rotl64(s0, 49) ^ s1 ^ (s1 << 21);
     *state1 = toilet_rotl64(s1, 28);
     return result;
 }

 static TOILET_FORCE_ABSORB uint64_t toilet_flush_entropy(
     SkibidiRngState* TOILET_NO_ALIAS rng)
 {
     return toilet_rng_next_words(&rng->s0[0], &rng->s1[0]);
 }

 #if TOILET_HAS_RIZZ_256
 /** Advance four independent streams in parallel with AVX2. */
 static TOILET_FORCE_ABSORB void toilet_quad_flush(
     SkibidiRngState* TOILET_NO_ALIAS rng,
     uint64_t* TOILET_NO_ALIAS dop_fuels)
 {
     __m256i s0 = _mm256_load_si256((const __m256i*)rng->s0);
     __m256i s1 = _mm256_load_si256((const __m256i*)rng->s1);
     __m256i sum = _mm256_add_epi64(s0, s1);
     __m256i result = _mm256_add_epi64(
         _mm256_or_si256(_mm256_slli_epi64(sum, 17), _mm256_srli_epi64(sum, 47)),
         s0);

     s1 = _mm256_xor_si256(s1, s0);
     __m256i next0 = _mm256_xor_si256(
         _mm256_xor_si256(
             _mm256_or_si256(_mm256_slli_epi64(s0, 49), _mm256_srli_epi64(s0, 15)),
             s1),
         _mm256_slli_epi64(s1, 21));
     __m256i next1 = _mm256_or_si256(
         _mm256_slli_epi64(s1, 28), _mm256_srli_epi64(s1, 36));

     _mm256_store_si256((__m256i*)rng->s0, next0);
     _mm256_store_si256((__m256i*)rng->s1, next1);
     _mm256_storeu_si256((__m256i*)dop_fuels, result);
 }
 #endif
 
 /** @} */
 
 /**
  * @defgroup DopCount The Branchless Dop Census Bureau
  * @brief Counting dops without a single branch, the toilet way
  * @{
  */
 
 /**
  * @brief Count dops using parallel comparisons (zero branches, full sigma)
  * 
  * This function determines how many times "dop" appears in the output
  * using nothing but arithmetic. No if-statements. No switch-cases.
  * No branches AT ALL. The branch predictor is unemployed. It has been
  * replaced by four parallel CMP instructions that all execute at once.
  * 
  * The toilet doesn't branch. The toilet doesn't hesitate. The toilet
  * KNOWS how many dops there are, instantly, through pure math.
  * 
  * Each comparison (vibes > threshold) returns 0 or 1.
  * Sum them up. Add 1. That's your dop count.
  * The toilet has spoken. The dops have been counted.
  * Branchless. Blameless. Flawless.
  * 
  * Threshold boundaries (the toilet's sacred numbers):
  * - vibes < 13:  1 dop (the toilet is shy today)
  * - vibes < 205: 2 dops (the canonical double dop, as the prophecy foretold)
  * - vibes < 231: 3 dops (the toilet is getting warmed up)
  * - vibes < 244: 4 dops (approaching critical dop mass)
  * - vibes >= 244: 5 DOPS (MAXIMUM DOP, THE TOILET IS SCREAMING)
  * 
  * Latency: ~2-3 cycles. The toilet counts faster than you can read this comment.
  * 
  * @param vibes 8-bit toilet entropy (0-255, the toilet's mood on a scale)
  * @return dop count in range [1, 5] (the toilet never produces zero dops, that would be nihilism)
  */
 static TOILET_FORCE_ABSORB int divine_dop_census(uint32_t vibes) {
     /*
      * The Four Parallel Judgments of the Toilet:
      * 
      * (vibes > 12)  -> "shall there be more than 1 dop?" -> 0 or 1
      * (vibes > 204) -> "shall there be more than 2 dops?" -> 0 or 1
      * (vibes > 230) -> "shall there be more than 3 dops?" -> 0 or 1
      * (vibes > 243) -> "shall there be more than 4 dops?" -> 0 or 1
      * 
      * Sum + 1 = the toilet's final answer
      * The CPU executes all 4 comparisons in parallel because they
      * are independent. The toilet is not sequential. The toilet
      * exists in all dop-states simultaneously until observed.
      * Schrodinger's Toilet. Skibidi quantum mechanics.
      */
     return 1 + (vibes > 12) + (vibes > 204) + (vibes > 230) + (vibes > 243);
 }
 
 /** @} */
 
 /**
  * @brief The Toilet Awakening Ceremony - executed once per process lifetime
  * 
  * When the first mortal calls any Skibidi API function, this ritual
  * fires. The toilet awakens from its eternal slumber, scans the CPU's
  * chakras via CPUID, and selects its SIMD battle strategy.
  * 
  * Strategy selection follows the Toilet Hierarchy of Needs:
  * 1. AVX-512: The toilet has achieved godhood, 512-bit dops
  * 2. AVX2: The toilet is a strong independent toilet, 256-bit dops
  * 3. Scalar: The toilet walks among mortals, one dop at a time
  * 
  * Uses double-checked locking because even the toilet respects
  * thread safety. The toilet is concurrent. The toilet is consistent.
  * The toilet is partition-tolerant. The toilet satisfies CAP theorem.
  * 
  * @note Marked TOILET_NPC because the toilet only awakens once. After that,
  *       it is always awake. Always watching. Always ready to dop.
  */
 static TOILET_FORCE_ABSORB void toilet_config_lock(void) {
     while (atomic_exchange_explicit(&g_toilet_hivemind.config_lock, 1,
                                     memory_order_acquire)) {
 #if TOILET_IS_X86
         __asm__ __volatile__("pause");
 #endif
     }
 }

 static TOILET_FORCE_ABSORB void toilet_config_unlock(void) {
     atomic_store_explicit(&g_toilet_hivemind.config_lock, 0,
                           memory_order_release);
 }

 static TOILET_NPC TOILET_BANISH void toilet_awakening_ceremony(void) {
     if (atomic_load_explicit(&g_toilet_hivemind.toilet_awake, memory_order_acquire)) {
         return;
     }

     toilet_config_lock();
     if (atomic_load_explicit(&g_toilet_hivemind.toilet_awake,
                              memory_order_relaxed)) {
         toilet_config_unlock();
         return;
     }
 
     uint32_t aura = scan_toilet_chakras();
     atomic_store_explicit(&g_toilet_hivemind.toilet_powers, aura, memory_order_relaxed);
 
     int battle_form = 0;
 
 #if TOILET_HAS_GODMODE_512
     if (aura & SKIBIDI_CAP_AVX512F) {
         battle_form = 2;
     } else
 #endif
 #if TOILET_HAS_RIZZ_256
     if (aura & SKIBIDI_CAP_AVX2) {
         battle_form = 1;
     }
 #endif
 
     atomic_store_explicit(&g_toilet_hivemind.flush_strategy,
                           battle_form, memory_order_relaxed);
     atomic_store_explicit(&g_toilet_hivemind.simd_rng_enabled,
                           1, memory_order_relaxed);
 
     atomic_thread_fence(memory_order_release);
     atomic_store_explicit(&g_toilet_hivemind.toilet_awake, 1, memory_order_release);
     toilet_config_unlock();
 }
 
 /**
  * @brief Quick vibe check: is the toilet awake?
  * 
  * Inline fast-path check with SKIBIDI_IMPROBABLE hint because after the first
  * call, the toilet is ALWAYS awake. The toilet does not go back to
  * sleep. The toilet has THAT DAWG IN IT. Once initialized, this
  * function costs exactly one atomic load + one branch (predicted
  * not-taken). The toilet values your CPU cycles.
  */
 static TOILET_FORCE_ABSORB void toilet_vibe_check(void) {
     if (SKIBIDI_IMPROBABLE(!atomic_load_explicit(&g_toilet_hivemind.toilet_awake, memory_order_acquire))) {
         toilet_awakening_ceremony();
     }
 }
 
 /**
  * @brief Inscribe a single dop/dom word onto the sacred buffer
  * 
  * Selects the word from the appropriate variant tablet (DOP or DOM)
  * and copies 3 characters using toilet_yeet_4 (the 4th byte is a harmless
  * null terminator that will be overwritten, like a toilet seat left up
  * that someone else will put down later).
  * 
  * The is_undercover_dom flag determines whether this particular dop has chosen
  * the dom life. 12.5% of dops make this choice. We do not judge.
  * The toilet accepts all words.
  * 
  * @param scroll The sacred inscription surface
  * @param chisel_pos Current chisel position on the surface
  * @param is_undercover_dom Has this dop gone dom? (12.5% chance, no cap)
  * @param zodiac_sign Which case variant universe this word exists in (0-7)
  * @return New position after the word (chisel_pos + 3, because 3 is the holy number)
  */
 static TOILET_FORCE_ABSORB int inscribe_dop_rune(
     char* TOILET_NO_ALIAS scroll,
     int chisel_pos,
     int is_undercover_dom,
     int zodiac_sign)
 {
     const char* rune_source = (is_undercover_dom ? DOM_DISGUISE_MULTIVERSE : DOP_MULTIVERSE) + (zodiac_sign << 2);
     toilet_yeet_4(scroll + chisel_pos, rune_source);
     return chisel_pos + 3;
 }

 #if TOILET_HAS_RIZZ_256
 static TOILET_FORCE_ABSORB int inscribe_batch_dop_rune(
     char* TOILET_NO_ALIAS scroll,
     int chisel_pos,
     uint32_t dom_draw,
     uint32_t zodiac_draw)
 {
     const uint32_t index = ((zodiac_draw & 0x1F) << 3) | (dom_draw & 0x7);
     const uint32_t rune = BATCH_DOP_ORACLE[index];
     __builtin_memcpy(scroll + chisel_pos, &rune, sizeof(rune));
     return chisel_pos + 3;
 }

 static TOILET_FORCE_ABSORB int inscribe_batch_ending(
     char* TOILET_NO_ALIAS scroll,
     int chisel_pos,
     uint32_t judgment_vibes,
     uint64_t entropy)
 {
     const int is_approval = judgment_vibes >= TOILET_REJECTION_THRESHOLD;
     const uint32_t approval_index = (uint32_t)(entropy >> 40) & 0x3FF;
     const uint32_t rejection_index = (uint32_t)(entropy >> 50) & 0x3FF;
     const uint32_t approval_mask = (uint32_t)-(int32_t)is_approval;
     const uint32_t variant_index = rejection_index ^
         ((rejection_index ^ approval_index) & approval_mask);
     const uint32_t index = variant_index | ((uint32_t)is_approval << 10);
     const uint64_t ending = BATCH_ENDINGS[index];
     __builtin_memcpy(scroll + chisel_pos, &ending, sizeof(ending));
     return chisel_pos + 6 + is_approval * 2;
 }
 #endif

 /**
  * @brief THE CORE TOILET ENGINE - where dops are born
  * 
  * This is it. This is the function. The alpha. The omega. The sigma.
  * Every Skibidi expression that has ever been or will ever be generated
  * passes through this function like a soul passing through the toilet
  * on its way to the afterlife.
  * 
  * Key toilet optimizations (in order of sigma-ness):
  * 1. Long-period xoroshiro128++ entropy with a four-lane AVX2 batch path
  * 2. Branchless dop count via parallel comparisons (no LUT, no cache miss, no mercy)
  * 3. Branchless prefix via conditional multiplication (chisel_pos = has_vibration * 7)
  * 4. Precomputed ending templates for the common lowercase case
  * 5. AVX2 32-byte copy when the prophecy (original expression) is chosen
  * 
  * Bit extraction map from toilet_entropy (the 64-bit toilet oracle):
  * - [63:56] The Dop Census: how many dops shall manifest?
  * - [55:48] Reserved structure entropy
  * - [47:40] The Brrrrr Oracle: does the toilet vibrate before speaking?
  * - [39:32] The Yes/No Tribunal: does the toilet approve or deny?
  * - [31:0]  The Prophecy Check: shall we speak the original words?
  * 
  * @param rng The toilet's consciousness (modified with each flush)
  * @param scroll The stone tablet upon which the dops shall be written
  * @param consult_prophecy Shall the calibrated dedicated fast path be enabled?
  * @return Length of the sacred inscription (not including null terminator because
  *         the toilet doesn't believe in null terminators, null terminators are
  *         for the weak, the toilet's words end when the toilet DECIDES they end)
  * 
  * @note Marked TOILET_MAIN_CHARACTER because this function runs hotter than a toilet
  *       after Taco Bell Tuesday. The compiler WILL optimize this.
  *       The compiler has no choice. The toilet has spoken.
  */
 static TOILET_MAIN_CHARACTER TOILET_FORCE_ABSORB int toilet_speak_ultra(
     SkibidiRngState* TOILET_NO_ALIAS rng,
     char* TOILET_NO_ALIAS scroll,
     int consult_prophecy)
 {
     uint64_t toilet_entropy = toilet_flush_entropy(rng);
 
     const uint32_t census_vibes      = (toilet_entropy >> 56) & 0xFF;
     const uint32_t prophecy_draw     = (uint32_t)toilet_entropy;
     const uint32_t vibration_vibes   = (toilet_entropy >> 40) & 0xFF;
     const uint32_t judgment_vibes    = (toilet_entropy >> 32) & 0xFF;
 
     /**
      * The calibrated direct path and natural reconstruction together produce
      * the canonical "Skibidi dop dop dop yes yes!" 40.0000000061% of the time.
      * No variations. No mutations. Just the raw, uncut prophecy.
      * We copy it with AVX2 if possible (32 bytes, one instruction,
      * the toilet moves at the speed of light).
      */
     if (consult_prophecy && SKIBIDI_IMPROBABLE(prophecy_draw < PROPHECY_THRESHOLD_NICE)) {
 #if TOILET_HAS_RIZZ_256
         if (SKIBIDI_PROBABLE(
                 atomic_load_explicit(&g_toilet_hivemind.flush_strategy,
                                      memory_order_relaxed) >= 1)) {
             toilet_omega_flush_32(scroll, SACRED_PROPHECY);
         } else
 #endif
         {
             toilet_yeet_32(scroll, SACRED_PROPHECY);
         }
         return PROPHECY_SACRED_LENGTH;
     }
 
     int chisel_pos = 0;
 
     /**
      * BRANCHLESS PREFIX TECHNIQUE (the toilet's signature move):
      * 
      * We ALWAYS write "Brrrrr " to the buffer. ALWAYS. Even when we
      * don't want it. Then we set chisel_pos to either 7 (keep it) or 0
      * (overwrite it with "Skibidi "). This is branchless. The branch
      * predictor is on vacation. The toilet handles this alone.
      * 
      * chisel_pos = has_vibration * 7
      * 
      * If has_vibration is 0: chisel_pos = 0, "Skibidi " overwrites "Brrrrr "
      * If has_vibration is 1: chisel_pos = 7, "Skibidi " goes after "Brrrrr "
      * 
      * The toilet doesn't ask IF. The toilet just DOES.
      */
     const int has_vibration = (consult_prophecy ? vibration_vibes :
                                ((uint32_t)(toilet_entropy >> 48) & 0xFF)) <
                               BRRRRR_VIBRATION_THRESHOLD;
     toilet_yeet_8(scroll, TOILET_VIBRATION_PREFIX);
     chisel_pos = has_vibration * 7;
 
     toilet_yeet_8(scroll + chisel_pos, TOILET_GOD_NAME);
     chisel_pos += 8;
 
    const int dop_population = divine_dop_census(census_vibes);
 
     uint64_t variant_entropy = toilet_flush_entropy(rng);
 
     /**
      * DOM infiltration bits: 3 bits per dop, if all 3 are zero (12.5%)
      * the dop secretly becomes a dom. The dom is a deep cover agent.
      * It looks like a dop. It sounds like a dop (almost). But its
      * third letter tells the truth. 'p' becomes 'm'. The toilet knows.
      */
     const uint32_t dom_infiltration = (uint32_t)variant_entropy;
 
     /**
      * Case variant bits: 5 bits per dop, fed into DOP_ZODIAC_CHART to
      * determine the dop's capitalization destiny. 78.125% remain
      * lowercase NPCs. 21.875% achieve main character capitalization.
      */
     const uint32_t zodiac_bits = (uint32_t)(variant_entropy >> 20);
 
     {
         int is_undercover_dom = (dom_infiltration & 0x7) == 0;
         int zodiac_sign = DOP_ZODIAC_CHART[zodiac_bits & 0x1F];
         chisel_pos = inscribe_dop_rune(scroll, chisel_pos, is_undercover_dom, zodiac_sign);
     }
 
     /**
      * The Dop Multiplication Cascade:
      * 
      * Each additional dop gets a space prefix and its own dom/variant
      * determination. The if-chain is structured by probability:
      * - 2nd dop: 95% chance (SKIBIDI_PROBABLE, the toilet almost always double-dops)
      * - 3rd dop: 20% chance (SKIBIDI_IMPROBABLE, the toilet is getting ambitious)
      * - 4th dop: 10% chance (the toilet has entered sicko mode)
      * - 5th dop: 5% chance (MAXIMUM DOP OVERLOAD, the toilet is screaming
      *   into the void with 5 consecutive dops and the cameraman's
      *   recording equipment has caught fire)
      */
     if (SKIBIDI_PROBABLE(dop_population >= 2)) {
         scroll[chisel_pos++] = ' ';
         int is_undercover_dom = ((dom_infiltration >> 3) & 0x7) == 0;
         int zodiac_sign = DOP_ZODIAC_CHART[(zodiac_bits >> 5) & 0x1F];
         chisel_pos = inscribe_dop_rune(scroll, chisel_pos, is_undercover_dom, zodiac_sign);
 
         if (SKIBIDI_IMPROBABLE(dop_population >= 3)) {
             scroll[chisel_pos++] = ' ';
             is_undercover_dom = ((dom_infiltration >> 6) & 0x7) == 0;
             zodiac_sign = DOP_ZODIAC_CHART[(zodiac_bits >> 10) & 0x1F];
             chisel_pos = inscribe_dop_rune(scroll, chisel_pos, is_undercover_dom, zodiac_sign);
 
             if (dop_population >= 4) {
                 scroll[chisel_pos++] = ' ';
                 is_undercover_dom = ((dom_infiltration >> 9) & 0x7) == 0;
                 zodiac_sign = DOP_ZODIAC_CHART[(zodiac_bits >> 15) & 0x1F];
                 chisel_pos = inscribe_dop_rune(scroll, chisel_pos, is_undercover_dom, zodiac_sign);
 
                 if (dop_population >= 5) {
                     scroll[chisel_pos++] = ' ';
                     is_undercover_dom = ((dom_infiltration >> 12) & 0x7) == 0;
                     zodiac_sign = DOP_ZODIAC_CHART[(zodiac_bits >> 20) & 0x1F];
                     chisel_pos = inscribe_dop_rune(scroll, chisel_pos, is_undercover_dom, zodiac_sign);
                 }
             }
         }
     }
 
     /**
      * THE ENDING - The Toilet's Final Judgment
      * 
      * The toilet decides: "yes yes!" (approval, 85%) or "no no!" (rejection, 15%).
      * 
      * In the common case, both words are lowercase, and we blast the
      * precomputed 8-byte template into the buffer. No per-character copies.
      * No variant lookups. Just 8 bytes of instant judgment. The toilet
      * has already decided. The toilet decided before you even called
      * this function. The toilet exists outside of time.
      */
     scroll[chisel_pos++] = ' ';
 
     const uint32_t tribunal_verdict = consult_prophecy ? judgment_vibes :
                                ((uint32_t)(toilet_entropy >> 40) & 0xFF);
 
     if (SKIBIDI_PROBABLE(tribunal_verdict >= TOILET_REJECTION_THRESHOLD)) {
         const uint32_t approval_vibe_1 = (variant_entropy >> 40) & 0x1F;
         const uint32_t approval_vibe_2 = (variant_entropy >> 45) & 0x1F;
 
         if (SKIBIDI_PROBABLE(approval_vibe_1 < 25 && approval_vibe_2 < 25)) {
             /**
              * FAST PATH: both yes-words are lowercase NPCs (~65%)
              * Slam the precomputed "yes yes!" template. 8 bytes. Done.
              * The toilet approves your existence. Rejoice.
              */
             toilet_yeet_8(scroll + chisel_pos, INSTANT_TOILET_APPROVAL);
             chisel_pos += 8;
         } else {
             int yes_zodiac_1 = DOP_ZODIAC_CHART[approval_vibe_1];
             int yes_zodiac_2 = DOP_ZODIAC_CHART[approval_vibe_2];
             toilet_yeet_4(scroll + chisel_pos, TOILET_APPROVAL_MULTIVERSE + (yes_zodiac_1 << 2));
             chisel_pos += 3;
             scroll[chisel_pos++] = ' ';
             toilet_yeet_4(scroll + chisel_pos, TOILET_APPROVAL_MULTIVERSE + (yes_zodiac_2 << 2));
             chisel_pos += 3;
             scroll[chisel_pos++] = '!';
         }
     } else {
         /**
          * THE REJECTION PATH: the toilet says "no no!" (15%)
          * The dops were not enough. The toilet is disappointed.
          * The cameraman takes his L and goes home.
          */
         const uint32_t rejection_vibe_1 = (variant_entropy >> 50) & 0x1F;
         const uint32_t rejection_vibe_2 = (variant_entropy >> 55) & 0x1F;
 
         if (SKIBIDI_PROBABLE(rejection_vibe_1 < 26 && rejection_vibe_2 < 26)) {
             toilet_yeet_8(scroll + chisel_pos, INSTANT_TOILET_REJECTION);
             chisel_pos += 6;
         } else {
             int no_zodiac_1 = REJECTION_ZODIAC_CHART[rejection_vibe_1];
             int no_zodiac_2 = REJECTION_ZODIAC_CHART[rejection_vibe_2];
             toilet_yeet_2(scroll + chisel_pos, TOILET_REJECTION_MULTIVERSE + (no_zodiac_1 << 2));
             chisel_pos += 2;
             scroll[chisel_pos++] = ' ';
             toilet_yeet_2(scroll + chisel_pos, TOILET_REJECTION_MULTIVERSE + (no_zodiac_2 << 2));
             chisel_pos += 2;
             scroll[chisel_pos++] = '!';
         }
     }
 
     return chisel_pos;
 }
 
 #if TOILET_HAS_RIZZ_256
 /**
  * @brief THE BATCH-OPTIMIZED ENTROPY CONSUMER - pre-generated randomness edition
  * 
  * This function is the toilet_speak_ultra's enlightened sibling, born from
  * the sacred realization that calling RNG twice per expression in batch mode
  * is like flushing twice when once would suffice. A waste of cycles. A waste
  * of toilet energy. An affront to the Skibidi gods.
  * 
  * The key insight: when generating expressions in batches, we can pre-generate
  * all entropy upfront using two four-lane RNG advances,
  * then feed them directly to this function. Zero additional RNG calls.
  * The toilet has achieved entropy nirvana.
  * 
  * This function accepts two 64-bit entropy values:
  * - entropy1: The primary oracle (dop count, prefix decision, yes/no verdict)
  * - entropy2: The variant oracle (dom infiltration, case zodiac, ending variants)
  * 
  * Together they contain 128 bits of pre-generated toilet wisdom, enough to
  * manifest a complete Skibidi expression without touching the RNG state.
  * The batch generator calls toilet_quad_flush twice, gets 8 random numbers,
  * and feeds pairs of them here. Pure efficiency. Pure sigma.
  * 
  * Bit extraction from entropy1 (the primary toilet oracle):
  * - [63:56] census_vibes: how many dops shall emerge from the porcelain depths
  * - [47:40] vibration_vibes: shall the toilet emit "Brrrrr" before speaking
  * - [39:32] judgment_vibes: the final verdict - approval or rejection
  * 
  * Bit extraction from entropy2 (the variant toilet oracle):
  * - [31:0] dom_infiltration: which dops are secretly doms (3 bits each, 12.5% chance)
  * - [51:20] zodiac_bits: case variant destiny for each dop (5 bits each)
  * - [50:40] ending variant bits: case variants for yes/no words
  * 
  * @param scroll The sacred parchment awaiting inscription
  * @param entropy1 Pre-generated primary entropy (from toilet_quad_flush output)
  * @param entropy2 Pre-generated variant entropy (from second toilet_quad_flush)
  * @return Length of the manifestation in bytes
  * 
  * @note This function NEVER calls toilet_flush_entropy. It is entropy-celibate.
  *       All randomness comes from above (the caller). This is the way.
  * @note Used exclusively by toilet_factory_avx2 for batch operations
  */
static TOILET_MAIN_CHARACTER TOILET_FORCE_ABSORB int toilet_speak_with_entropy(
     char* TOILET_NO_ALIAS scroll,
     uint64_t entropy1,
     uint64_t entropy2)
 {
     const uint32_t census_vibes    = (entropy1 >> 56) & 0xFF;
     const uint32_t vibration_vibes = (entropy1 >> 40) & 0xFF;
     const uint32_t judgment_vibes  = (entropy1 >> 32) & 0xFF;

     int chisel_pos = 0;

     const int has_vibration = vibration_vibes < BRRRRR_VIBRATION_THRESHOLD;
     toilet_yeet_8(scroll, TOILET_VIBRATION_PREFIX);
     chisel_pos = has_vibration * 7;

     toilet_yeet_8(scroll + chisel_pos, TOILET_GOD_NAME);
     chisel_pos += 8;

     const int dop_population = DOP_CENSUS_ORACLE[census_vibes];

     const uint32_t dom_infiltration = (uint32_t)entropy2;
     const uint32_t zodiac_bits = (uint32_t)(entropy2 >> 20);
 
     {
         chisel_pos = inscribe_batch_dop_rune(
             scroll, chisel_pos, dom_infiltration, zodiac_bits);
     }

     if (SKIBIDI_PROBABLE(dop_population >= 2)) {
         scroll[chisel_pos++] = ' ';
         chisel_pos = inscribe_batch_dop_rune(
             scroll, chisel_pos, dom_infiltration >> 3, zodiac_bits >> 5);

         const int rare_dop_base = chisel_pos;
         switch (dop_population) {
             case 5:
                 (void)inscribe_batch_dop_rune(
                     scroll, rare_dop_base + 9, dom_infiltration >> 12,
                     zodiac_bits >> 20);
                 __attribute__((fallthrough));
             case 4:
                 (void)inscribe_batch_dop_rune(
                     scroll, rare_dop_base + 5, dom_infiltration >> 9,
                     zodiac_bits >> 15);
                 scroll[rare_dop_base + 8] = ' ';
                 __attribute__((fallthrough));
             case 3:
                 (void)inscribe_batch_dop_rune(
                     scroll, rare_dop_base + 1, dom_infiltration >> 6,
                     zodiac_bits >> 10);
                 scroll[rare_dop_base + 4] = ' ';
                 scroll[rare_dop_base] = ' ';
                 chisel_pos += (dop_population - 2) * 4;
                 break;
             default:
                 break;
         }
     }

     scroll[chisel_pos++] = ' ';
     return inscribe_batch_ending(scroll, chisel_pos, judgment_vibes, entropy2);
 }
 
 /**
  * @brief Four-record AVX2 batch generator
  *
  * Two vector RNG advances provide structure and variant entropy for four
  * records. Prophecy classification is vectorized; materialization remains
  * scalar because each record has a variable compacted output offset.
  * 
  * @param ctx The supreme toilet context, holder of all RNG state
  * @param scroll The great parchment upon which the dops shall flow
  * @param scroll_capacity The parchment's capacity in bytes
  * @param quota The number of expressions the mortal desires
  * @param inscription_lengths Optional array for recording each expression's length
  * @return The number of expressions successfully manifested
  * 
  * @note Falls back to scalar loop for the final stragglers (quota % 4)
  */
 static TOILET_MAIN_CHARACTER int toilet_factory_avx2(
     SkibidiContext* TOILET_NO_ALIAS ctx,
     char* TOILET_NO_ALIAS scroll,
     size_t scroll_capacity,
     int quota,
     int* TOILET_NO_ALIAS inscription_lengths)
 {
     SkibidiRngState* rng = &ctx->rng;
     int toilets_flushed = 0;
     size_t scroll_offset = 0;

     /* Extract and compare the independent 32-bit prophecy draws in four lanes. */
     const __m256i prophecy_threshold =
         _mm256_set1_epi64x((uint64_t)PROPHECY_THRESHOLD_NICE);
     const __m256i prophecy_mask_bits = _mm256_set1_epi64x(UINT32_MAX);
 
     /*
      * MAIN BATCH LOOP: Process 4 expressions per iteration
      * 
      * Each iteration:
      * 1. Pre-generate 8 random numbers via 2x toilet_quad_flush (ILP-optimized)
      * 2. SIMD-detect which of the 4 hit the prophecy fast path
      * 3. Generate each expression using pre-generated entropy
      * 4. Record lengths and append newlines
      * 
      * The loop continues while we have room for 4 more expressions and
      * buffer space for 4 worst-case outputs.
      */
     while (toilets_flushed + 4 <= quota && 
             scroll_offset + 4 * SKIBIDI_BATCH_RECORD_CAPACITY <= scroll_capacity) {
 
         /*
          * Two four-lane xoroshiro128++ advances provide eight entropy words.
          * 
          * entropy1[0..3]: Primary entropy for expressions 0-3
          *   - [63:56]: dop census (how many dops)
          *   - [47:40]: vibration vibes
          *   - [39:32]: judgment vibes (yes/no decision)
          *   - [31:0]:  calibrated prophecy draw
          * 
          * entropy2[0..3]: Variant entropy for expressions 0-3
          *   - [31:0]:  dom infiltration bits
          *   - [51:20]: zodiac/case variant bits
          *   - [63:40]: ending variant bits
          * 
          */
         uint64_t entropy1[4] __attribute__((aligned(32)));
         uint64_t entropy2[4] __attribute__((aligned(32)));
         
         toilet_quad_flush(rng, entropy1);
         toilet_quad_flush(rng, entropy2);
 
         /*
          * SIMD PROPHECY DETECTION (THE FOUR-WAY JUDGMENT):
          * 
          * 1. Load all 4 entropy1 values into a 256-bit YMM register
          * 2. AND with a 32-bit mask to extract the independent draw
          * 3. Compare against threshold 1,680,443,541 using greater-than
          * 4. Extract comparison results as a 4-bit mask
          * 
          * If bit i of prophecy_mask is set, expression i hit the prophecy.
          * 39.1258751275% direct hit rate per expression.
          * 
          * Instructions:
          *   vmovdqa (%entropy1), %ymm0       ; load 4 entropy values
          *   vpand   %ymm_mask, %ymm0, %ymm1  ; extract prophecy bits
          *   vpcmpgtq %ymm1, %ymm_thresh, %ymm2 ; compare all 4
          *   vmovmskpd %ymm2, %eax            ; extract 4-bit mask
          * 
         * Four branches become one SIMD operation. The toilet has transcended.
         */
         __m256i entropy_vec = _mm256_load_si256((const __m256i*)entropy1);
         __m256i masked = _mm256_and_si256(entropy_vec, prophecy_mask_bits);
         __m256i cmp_result = _mm256_cmpgt_epi64(prophecy_threshold, masked);
         uint32_t prophecy_mask = (uint32_t)_mm256_movemask_pd(_mm256_castsi256_pd(cmp_result));

         /*
          * EXPRESSION GENERATION LOOP:
          * 
          * For each of the 4 expressions in this batch:
          * - If prophecy bit is set: AVX2-copy the sacred prophecy (32 bytes, 2 instructions)
          * - Otherwise: call toilet_speak_with_entropy with pre-generated entropy
          * 
          * The key optimization: toilet_speak_with_entropy NEVER calls RNG.
          * All entropy was pre-generated above. The function just consumes
          * the bits and writes the expression. Pure, RNG-free generation.
          */
 #pragma GCC unroll 4
         for (int i = 0; i < 4; i++) {
             char* output = scroll + scroll_offset;
             int len;

             if ((prophecy_mask >> i) & 1) {
                 /*
                  * PROPHECY FAST PATH:
                  * The oracle has spoken. Copy the sacred 28-byte incantation
                  * using a single 32-byte AVX2 operation. The extra 4 bytes
                  * are harmless overflow (null bytes). Speed over purity.
                  */
                 toilet_omega_flush_32(output, SACRED_PROPHECY);
                 len = PROPHECY_SACRED_LENGTH;
             } else {
                 /*
                  * VARIANT PATH:
                  * Generate a unique expression using pre-generated entropy.
                  * entropy1[i] provides structure, entropy2[i] provides variants.
                  * Zero RNG calls. The entropy has already been blessed.
                  */
                 len = toilet_speak_with_entropy(output, entropy1[i], entropy2[i]);
             }
 
             /* Bookkeeping: the necessary overhead of batch operations */
             if (inscription_lengths) {
                 inscription_lengths[toilets_flushed] = len;
             }
             output[len] = '\n';
             scroll_offset += len + 1;
             toilets_flushed++;
         }
     }
 
     /*
      * STRAGGLER LOOP: Handle remaining expressions (quota % 4)
      * 
      * When the quota isn't divisible by 4, we fall back to the standard
      * toilet_speak_ultra for the remaining 1-3 expressions. This path
      * uses the traditional 2-RNG-calls-per-expression approach, but
      * it only runs for at most 3 expressions, so the overhead is minimal.
      * 
      * The toilet does not leave stragglers behind. Every dop matters.
      */
     while (toilets_flushed < quota && 
             scroll_offset + SKIBIDI_BATCH_RECORD_CAPACITY <= scroll_capacity) {
         
         int len = toilet_speak_ultra(rng, scroll + scroll_offset, 1);
         if (inscription_lengths) {
             inscription_lengths[toilets_flushed] = len;
         }
         scroll[scroll_offset + len] = '\n';
         scroll_offset += len + 1;
         toilets_flushed++;
     }
 
     ctx->call_count += (uint64_t)toilets_flushed;
     return toilets_flushed;
 }
 
 #endif /* TOILET_HAS_RIZZ_256 */
 
 /**
  * @brief Birth a Skibidi Toilet context into the world
  * 
  * This function is the toilet's genesis moment. From a single 64-bit
  * seed, it creates 4 independent RNG channels using SplitMix64,
  * an algorithm that takes one number and splits it into many numbers,
  * much like how one toilet spawned the entire Skibidi multiverse.
  * 
  * Each lane receives two SplitMix64 outputs. xoroshiro128++ only forbids
  * the all-zero state, which is repaired explicitly if it ever occurs.
  * 
  * @param ctx The vessel that shall contain the toilet's consciousness
  * @param seed The primordial number from which all dops shall flow
  * @return SKIBIDI_OK if the toilet was born successfully,
  *         SKIBIDI_ERR_NULL_PTR if you tried to birth a toilet into the void
  * 
  * @note Same seed = same dops forever. The toilet is deterministic.
  *       The toilet does not believe in free will. Only in dops.
  * @see skibidi_destroy for when the toilet's time has come
  */
 static TOILET_FORCE_ABSORB uint64_t toilet_splitmix64_next(uint64_t* state) {
     uint64_t value = (*state += UINT64_C(0x9E3779B97F4A7C15));
     value = (value ^ (value >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
     value = (value ^ (value >> 27)) * UINT64_C(0x94D049BB133111EB);
     return value ^ (value >> 31);
 }

 int skibidi_init(SkibidiContext* ctx, uint64_t seed) {
     if (SKIBIDI_IMPROBABLE(!ctx)) return SKIBIDI_ERR_NULL_PTR;
 
     toilet_vibe_check();
 
     memset(ctx, 0, sizeof(SkibidiContext));
 
     /**
      * SplitMix64 seed expansion: one seed becomes 8 independent states.
      * 
      * The golden ratio constant 0x9E3779B97F4A7C15 is used to space
      * the seeds apart. This constant appears in hash tables, PRNGs,
      * and now, toilet initialization. The golden ratio is truly golden.
      * The toilet appreciates mathematical beauty.
      */
     uint64_t seed_stream = seed;
     for (int reincarnation = 0; reincarnation < 4; reincarnation++) {
         ctx->rng.s0[reincarnation] = toilet_splitmix64_next(&seed_stream);
         ctx->rng.s1[reincarnation] = toilet_splitmix64_next(&seed_stream);
         if ((ctx->rng.s0[reincarnation] | ctx->rng.s1[reincarnation]) == 0) {
             ctx->rng.s1[reincarnation] = UINT64_C(0x9E3779B97F4A7C15);
         }
     }
 
     ctx->rng.buffer_idx = 0;
 
     return SKIBIDI_OK;
 }
 
 /**
  * @brief Reconfigure the global toilet to the user's specifications
  * 
  * Allows the mortal to tell the toilet which SIMD dimension to
  * flush through. The enable_avx512 flag is basically asking the
  * toilet "are you SURE you want to go ultra instinct?" because
  * AVX-512 toilets sometimes cause frequency throttling and the
  * CPU gets sleepy after too much 512-bit flushing.
  * 
  * @param config The mortal's humble toilet configuration request
  * @return SKIBIDI_OK if the toilet accepted the reconfiguration,
  *         SKIBIDI_ERR_NULL_PTR if the mortal forgot to bring a config
  * 
  * @warning Existing toilet contexts will continue flushing with their
  *          old settings. You must re-init each toilet (call skibidi_init)
  *          for the new configuration to take effect. The toilet respects
  *          existing commitments. The toilet has honor.
  * 
  * @note AVX-512 activation requires a triple conjunction:
  *       1. The CPU's silicon must contain the AVX-512 runes (CPUID)
  *       2. The compiler must have been given -mavx512f (compile-time pact)
  *       3. The config must say enable_avx512 = 1 (the mortal's consent)
  *       All three must align, like the stars, like the toilets.
  */
 int skibidi_configure(const SkibidiConfig* config) {
     if (SKIBIDI_IMPROBABLE(!config)) return SKIBIDI_ERR_NULL_PTR;
 
     toilet_config_lock();
 
     uint32_t aura = scan_toilet_chakras();
     atomic_store_explicit(&g_toilet_hivemind.toilet_powers, aura, memory_order_relaxed);
 
     int battle_form = 0;
 
 #if TOILET_HAS_GODMODE_512
     if ((aura & SKIBIDI_CAP_AVX512F) && config->enable_avx512) {
         battle_form = 2;
     } else
 #endif
 #if TOILET_HAS_RIZZ_256
     if (aura & SKIBIDI_CAP_AVX2) {
         battle_form = 1;
     }
 #else
     (void)aura;
 #endif
 
     atomic_store_explicit(&g_toilet_hivemind.flush_strategy,
                           battle_form, memory_order_relaxed);
     atomic_store_explicit(&g_toilet_hivemind.simd_rng_enabled,
                           config->enable_simd_rng != 0, memory_order_relaxed);
 
     atomic_thread_fence(memory_order_release);
     atomic_store_explicit(&g_toilet_hivemind.toilet_awake, 1, memory_order_release);
     toilet_config_unlock();
 
     return SKIBIDI_OK;
 }
 
 /**
  * @brief Ask the toilet what configuration it's currently running
  * 
  * The toilet opens its porcelain heart and reveals its settings.
  * 
  * @param config Where the toilet shall disclose its secrets
  * @return SKIBIDI_OK always, unless you pass NULL, in which case the
  *         toilet judges you (SKIBIDI_ERR_NULL_PTR)
  */
 int skibidi_get_config(SkibidiConfig* config) {
     if (SKIBIDI_IMPROBABLE(!config)) return SKIBIDI_ERR_NULL_PTR;
 
     memset(config, 0, sizeof(SkibidiConfig));
     config->enable_avx512 =
         atomic_load_explicit(&g_toilet_hivemind.flush_strategy,
                              memory_order_relaxed) == 2;
     config->enable_simd_rng =
         atomic_load_explicit(&g_toilet_hivemind.simd_rng_enabled,
                              memory_order_relaxed) != 0;
     return SKIBIDI_OK;
 }
 
 /**
  * @brief Generate a single Skibidi expression (THE function. THE one.)
  * 
  * This is what you came here for. This is what the toilet was built for.
  * Call this function and receive a Skibidi expression. The calibrated
  * direct path plus natural random-path reconstruction gives a total
  * three-dop prophecy probability of 40.0000000061%.
  * 
  * @param ctx Your personal toilet (initialized with skibidi_init)
  * @param buffer Where the dops go (minimum SKIBIDI_MIN_BUFFER_SIZE bytes)
  * @param buffer_size How big your buffer is (the toilet will NOT overflow,
  *        unlike that one time at the office)
  * @return Length of the expression in bytes, or a negative number if you
  *         angered the toilet (NULL pointers, tiny buffers, etc.)
  * 
  * @note The buffer is NOT null-terminated. The toilet doesn't null-terminate.
  *       The toilet gives you a length. Use the length. Trust the length.
  *       The length is the toilet's promise. The length is truth.
  */
 TOILET_MAIN_CHARACTER int skibidi_generate(SkibidiContext* ctx, char* buffer, size_t buffer_size) {
     if (SKIBIDI_IMPROBABLE(!ctx | !buffer)) return SKIBIDI_ERR_NULL_PTR;
     if (SKIBIDI_IMPROBABLE(buffer_size < SKIBIDI_MIN_BUFFER_SIZE)) return SKIBIDI_ERR_BUFFER_TOO_SMALL;
 
     ctx->call_count++;
     return toilet_speak_ultra(&ctx->rng, buffer, 1);
 }
 
 /**
  * @brief Generate through the random path without the dedicated prophecy branch
  * 
  * Like skibidi_generate but the dedicated prophecy copy is skipped. The
  * random path still may naturally reconstruct "Skibidi dop dop dop yes yes!".
  * 
  * Use this when you want pure chaos. When the prophecy is too
  * mainstream. When you need that underground toilet energy.
  * 
  * @param ctx The toilet's vessel
  * @param buffer The canvas for the toilet's creativity
  * @param buffer_size Canvas dimensions (must accommodate the toilet's art)
  * @return Length of the toilet's unique artistic expression, or negative error
  */
 TOILET_MAIN_CHARACTER int skibidi_generate_variant(SkibidiContext* ctx, char* buffer, size_t buffer_size) {
     if (SKIBIDI_IMPROBABLE(!ctx | !buffer)) return SKIBIDI_ERR_NULL_PTR;
     if (SKIBIDI_IMPROBABLE(buffer_size < SKIBIDI_MIN_BUFFER_SIZE)) return SKIBIDI_ERR_BUFFER_TOO_SMALL;
 
     ctx->call_count++;
     return toilet_speak_ultra(&ctx->rng, buffer, 0);
 }
 
 /**
  * @brief MASS TOILET PRODUCTION: generate many expressions at once
  * 
  * When one dop is not enough. When you need a FLOOD of dops. When
  * the world needs to hear the toilet's message at industrial scale.
  * This function opens all the stalls and lets the dops flow like
  * water through the pipes of a building-sized Skibidi Toilet.
  * 
  * With AVX2 enabled, processes 4 expressions per iteration using
  * SIMD parallelism. Two 4-way RNG advances generate the entropy for
  * four expressions. The SIMD comparison detects prophecy fast paths across
  * all 4 toilets simultaneously. It's a toilet assembly line.
  * Henry Ford would be proud. Henry Ford would be confused. Henry
  * Ford would need therapy.
  * 
  * Output format: expressions separated by newlines because even in
  * mass production, the toilet believes in proper formatting.
  * 
  * @param ctx The factory foreman (toilet context)
  * @param buffer The warehouse (output buffer for ALL expressions)
  * @param buffer_size Warehouse capacity in bytes
  * @param count Production quota (maximum expressions to manufacture)
  * @param lengths Optional quality control log (individual lengths)
  * @return Actual production output (may be less if warehouse is full)
  * 
  * @note If the buffer runs out mid-production, the toilet gracefully
  *       stops. No half-dops. No incomplete expressions. The toilet
  *       has quality standards. The toilet has ISO 9001 certification.
  */
 int skibidi_generate_batch(SkibidiContext* ctx, char* buffer, 
                            size_t buffer_size, int count, int* lengths) {
     if (SKIBIDI_IMPROBABLE(!ctx | !buffer)) return 0;
     if (SKIBIDI_IMPROBABLE(buffer_size < SKIBIDI_MIN_BUFFER_SIZE)) return 0;
     if (SKIBIDI_IMPROBABLE(count <= 0)) return 0;
 
 #if TOILET_HAS_RIZZ_256
     if (atomic_load_explicit(&g_toilet_hivemind.simd_rng_enabled,
                              memory_order_relaxed) &&
         atomic_load_explicit(&g_toilet_hivemind.flush_strategy,
                              memory_order_relaxed) >= 1) {
         return toilet_factory_avx2(ctx, buffer, buffer_size, count, lengths);
     }
 #endif
 
     int toilets_flushed = 0;
     size_t scroll_offset = 0;
 
     for (int soul = 0;
          soul < count && scroll_offset + SKIBIDI_BATCH_RECORD_CAPACITY <= buffer_size;
          soul++) {
         int inscription_len = toilet_speak_ultra(&ctx->rng, buffer + scroll_offset, 1);
         if (SKIBIDI_IMPROBABLE(inscription_len < 0)) break;
 
         if (lengths) lengths[soul] = inscription_len;
         buffer[scroll_offset + inscription_len] = '\n';
         scroll_offset += inscription_len + 1;
         toilets_flushed++;
     }
 
     ctx->call_count += (uint64_t)toilets_flushed;
     return toilets_flushed;
 }
 
 /**
  * @brief End the toilet's existence (secure destruction)
  * 
  * The toilet's final flush. All memory is overwritten with zeros
  * using volatile writes so the compiler cannot optimize away the
  * toilet's death. The RNG state is obliterated. The dop counts
  * are forgotten. The toilet's consciousness returns to the void.
  * 
  * This is important for security because if someone reads the
  * toilet's RNG state from memory, they could predict future dops.
  * And in the wrong hands, predicted dops could be... well, actually
  * they'd just be Skibidi expressions. But the toilet takes OPSEC
  * seriously. The toilet has read the NIST guidelines.
  * 
  * @param ctx The toilet to destroy (NULL is accepted, even the void is valid)
  * 
  * @note The volatile keyword ensures the compiler doesn't say "lol
  *       nobody reads this memory after this function, I'll just skip
  *       the zeroing." NO. The toilet WILL be zeroed. The toilet's
  *       memory WILL be cleansed. The toilet demands a clean death.
  */
 void skibidi_destroy(SkibidiContext* ctx) {
     if (ctx) {
         volatile uint64_t* porcelain = (volatile uint64_t*)ctx;
         for (size_t shard = 0; shard < sizeof(SkibidiContext) / sizeof(uint64_t); shard++) {
             porcelain[shard] = 0;
         }
     }
 }
 
 /**
  * @brief Summon a properly aligned toilet from the heap dimension
  * 
  * Allocates a 64-byte-aligned context because the toilet demands
  * cache line alignment. An unaligned toilet is a sad toilet. A sad
  * toilet produces slow dops. We cannot allow slow dops.
  * 
  * @return A fresh toilet, aligned and ready for initialization,
  *         or NULL if the heap has no room for another toilet (tragic)
  * 
  * @note You MUST call skibidi_free_context to release the toilet
  *       when you're done. Leaked toilets are an environmental hazard.
  * @see skibidi_free_context for the toilet deallocation ceremony
  */
 SkibidiContext* skibidi_alloc_context(void) {
     return (SkibidiContext*)SKIBIDI_ALIGNED_ALLOC(64, sizeof(SkibidiContext));
 }
 
 /**
  * @brief Summon an entire BATTALION of aligned toilets
  * 
  * For multi-threaded Skibidi operations where each thread needs its
  * own toilet. All toilets are allocated in a contiguous block with
  * 64-byte alignment to prevent false sharing (when two threads
  * accidentally share a cache line with their toilets, causing
  * performance to drop and the toilets to argue).
  * 
  * @param count Number of toilets in the battalion
  * @return Pointer to the first toilet in the formation, or NULL if
  *         the heap cannot accommodate this many toilets
  * 
  * @note Each toilet must be individually initialized with skibidi_init.
  *       The toilets do not share consciousness. Each toilet is its own
  *       universe. Each toilet has its own dop destiny.
  * @note Use skibidi_free_context to dismiss the entire battalion at once
  */
 SkibidiContext* skibidi_alloc_context_array(size_t count) {
     if (count == 0) return NULL;
     return (SkibidiContext*)SKIBIDI_ALIGNED_ALLOC(64, count * sizeof(SkibidiContext));
 }
 
 /**
  * @brief Release a toilet back to the heap (with full funeral rites)
  * 
  * First destroys the toilet's consciousness (secure zeroing),
  * then frees the aligned memory back to the allocator. The toilet
  * is gone. The dops it generated live on in the buffers it wrote to.
  * The toilet's legacy is its dops. Remember the toilet's dops.
  * 
  * @param ctx The toilet to free (NULL is accepted, freeing nothing is free)
  */
 void skibidi_free_context(SkibidiContext* ctx) {
     if (ctx) {
         skibidi_destroy(ctx);
         SKIBIDI_ALIGNED_FREE(ctx);
     }
 }
 
 /**
  * @brief Reveal the toilet engine's version string
  * @return The version inscription on the toilet's porcelain base
  */
 const char* skibidi_version(void) {
     return TOILET_FIRMWARE_VERSION;
 }
 
 /**
  * @brief Ask the CPU: "bro do you even AVX2?"
  * @return Non-zero if the CPU has unlocked the 256-bit toilet dimension
  */
 int skibidi_has_avx2(void) {
     toilet_vibe_check();
     return (atomic_load_explicit(&g_toilet_hivemind.toilet_powers, memory_order_relaxed) & 
             SKIBIDI_CAP_AVX2) != 0;
 }
 
 /**
  * @brief Ask the CPU: "have you achieved AVX-512 toilet transcendence?"
  * @return Non-zero if the CPU has entered the 512-bit shadow realm
  */
 int skibidi_has_avx512(void) {
     toilet_vibe_check();
     return (atomic_load_explicit(&g_toilet_hivemind.toilet_powers, memory_order_relaxed) & 
             SKIBIDI_CAP_AVX512F) != 0;
 }
 
 /**
  * @brief Read the CPU's complete toilet power level (it's over 9000)
  * @return Bitmask of SKIBIDI_CAP_* flags representing the CPU's toilet chi
  */
 uint32_t skibidi_get_capabilities(void) {
     toilet_vibe_check();
     return atomic_load_explicit(&g_toilet_hivemind.toilet_powers, memory_order_relaxed);
 }
 
 /**
  * @brief Which toilet dimension are we flushing through right now?
  * @return "AVX-512" (godmode), "AVX2" (sigma), or "Scalar" (literally Ohio)
  */
 const char* skibidi_get_active_simd(void) {
     toilet_vibe_check();
     switch (atomic_load_explicit(&g_toilet_hivemind.flush_strategy,
                                  memory_order_relaxed)) {
         case 2:  return "AVX-512";
         case 1:  return "AVX2";
         default: return "Scalar";
     }
 }
 
 /**
  * @brief Is the toilet currently in AVX-512 ultra instinct mode?
  * @return Non-zero if the toilet has gone beyond, plus ultra, final form
  */
 int skibidi_is_avx512_enabled(void) {
     toilet_vibe_check();
     return atomic_load_explicit(&g_toilet_hivemind.flush_strategy,
                                 memory_order_relaxed) == 2;
 }
 
 /**
  * @brief How many bytes does the toilet's brain occupy?
  * @return Size of SkibidiRngState in bytes (the toilet's cranial capacity)
  */
 size_t skibidi_get_rng_state_size(void) {
     return sizeof(SkibidiRngState);
 }
 
 /**
  * @brief How many bytes does the entire toilet body occupy?
  * @return Size of SkibidiContext in bytes (the toilet's BMI, basically)
  */
 size_t skibidi_get_context_size(void) {
     return sizeof(SkibidiContext);
 }
 
 /**
  * @brief What alignment does the toilet require for optimal feng shui?
  * @return Alignment in bytes (64, because the toilet respects cache line boundaries
  *         and the cache line respects the toilet, it's a mutual respect situation)
  */
 size_t skibidi_get_context_alignment(void) {
     return _Alignof(SkibidiContext);
 }
