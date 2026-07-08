#ifndef WTQ_TEST_SCENARIO_H
#define WTQ_TEST_SCENARIO_H

/*
 * Shared scenario runner for the public-API rail. A suite is a table of
 * named scenarios plus a fixed seed set; the runner enforces the same
 * discipline for every suite (conformance, faults):
 *   - each scenario runs across every seed;
 *   - same seed twice -> byte-identical full trace (reproducibility);
 *   - a scenario marked deterministic -> stable semantic hash across
 *     seeds (outcome independent of delivery chunking);
 *   - the engine_errors count matches the scenario's declared value;
 *   - the counting allocator balances to zero after teardown;
 *   - a pinned golden semantic hash (when set) matches.
 *
 * argv drives selection: none = all, <name> = one, --hashes = dump each
 * scenario's semantic hash at the first seed (for pinning goldens).
 */

#include "wtq_apipair.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*wtq_scenario_fn)(wtq_apipair_t *p);

typedef struct wtq_scenario {
    const char *name;
    wtq_scenario_fn fn;
    int expected_engine_errors;
    bool deterministic;   /* cross-seed semantic hash is stable */
    uint64_t golden;      /* pinned semantic hash (0 = not pinned) */
} wtq_scenario_t;

/* Run the table per argv; returns the process exit code (0 pass, 1
 * failures, 2 unknown scenario name). suite labels the PASS/FAIL line. */
int wtq_scenario_main(const wtq_scenario_t *table, size_t count,
                      const uint64_t *seeds, size_t nseeds,
                      const char *suite, int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_TEST_SCENARIO_H */
