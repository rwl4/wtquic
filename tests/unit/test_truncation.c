/*
 * Exhaustive truncation + single-bit mutation over every committed
 * wire vector.
 *
 * Truncation: every strict prefix of every vector must produce a clean
 * documented status; for single-object incremental types (capsules,
 * preambles) a strict prefix of a positive vector must never decode as
 * complete.
 *
 * Mutation: every byte x {bit0, bit7} flip must produce a clean status
 * — a deterministic mini-fuzz that runs per-PR (the ASan lane gives it
 * memory teeth).
 */

#include <stdio.h>
#include <string.h>

#include "wt15_vectors.h"

int main(void)
{
    static wt15_vector_t vec[WT15_MAX_VECTORS];
    size_t count = wt15_vectors_build(vec, WT15_MAX_VECTORS);
    int failures = 0;
    size_t truncation_cases = 0;
    size_t mutation_cases = 0;

    for (size_t i = 0; i < count; i++) {
        /* every strict prefix */
        for (size_t plen = 0; plen < vec[i].wire_len; plen++) {
            failures += wt15_vector_feed_hostile(&vec[i], vec[i].wire,
                                                 plen, true);
            truncation_cases++;
        }

        /* every byte, bit 0 and bit 7 flipped */
        uint8_t mutated[WT15_MAX_WIRE];
        for (size_t b = 0; b < vec[i].wire_len; b++) {
            for (int bit = 0; bit < 8; bit += 7) {
                memcpy(mutated, vec[i].wire, vec[i].wire_len);
                mutated[b] ^= (uint8_t)(1u << bit);
                failures += wt15_vector_feed_hostile(&vec[i], mutated,
                                                     vec[i].wire_len,
                                                     false);
                mutation_cases++;
            }
        }
    }

    if (failures == 0)
        printf("PASS: test_truncation (%zu vectors, %zu truncations, "
               "%zu mutations)\n", count, truncation_cases,
               mutation_cases);
    return failures;
}
