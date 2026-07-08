#include "wtq_scenario.h"

#include <stdio.h>
#include <string.h>

static int run_once(const wtq_scenario_t *sc, uint64_t seed,
                    uint64_t *trace_hash, uint64_t *sem_hash)
{
    static wtq_apipair_t p;
    int failures = 0;

    if (wtq_apipair_create(&p, seed) != 0) {
        fprintf(stderr, "  rail create failed\n");
        return 1;
    }
    failures += sc->fn(&p);
    if (p.engine_errors != sc->expected_engine_errors) {
        fprintf(stderr, "  [%s] engine_errors=%d expected=%d\n", sc->name,
                p.engine_errors, sc->expected_engine_errors);
        failures++;
    }
    if (p.overflow) {
        fprintf(stderr, "  [%s] trace overflow\n", sc->name);
        failures++;
    }
    if (trace_hash != NULL)
        *trace_hash = wtq_apipair_trace_hash(&p);
    if (sem_hash != NULL)
        *sem_hash = wtq_apipair_semantic_hash(&p);
    wtq_apipair_destroy(&p);
    if (p.allocs != p.frees) {
        fprintf(stderr, "  [%s] alloc imbalance: %d != %d\n", sc->name,
                p.allocs, p.frees);
        failures++;
    }
    return failures;
}

static int run_scenario(const wtq_scenario_t *sc, const uint64_t *seeds,
                        size_t nseeds)
{
    int failures = 0;
    uint64_t sem0 = 0;

    for (size_t i = 0; i < nseeds; i++) {
        uint64_t th1 = 0, th2 = 0, sh = 0;
        failures += run_once(sc, seeds[i], &th1, &sh);
        /* same seed twice: byte-identical trace */
        failures += run_once(sc, seeds[i], &th2, NULL);
        if (th1 != th2) {
            fprintf(stderr, "  [%s] seed 0x%llx trace not reproducible\n",
                    sc->name, (unsigned long long)seeds[i]);
            failures++;
        }
        if (i == 0)
            sem0 = sh;
        else if (sc->deterministic && sh != sem0) {
            fprintf(stderr, "  [%s] semantic hash varies across seeds\n",
                    sc->name);
            failures++;
        }
    }
    if (sc->golden != 0 && sem0 != sc->golden) {
        fprintf(stderr, "  [%s] golden mismatch: got 0x%llx want 0x%llx\n",
                sc->name, (unsigned long long)sem0,
                (unsigned long long)sc->golden);
        failures++;
    }
    return failures;
}

int wtq_scenario_main(const wtq_scenario_t *table, size_t count,
                      const uint64_t *seeds, size_t nseeds,
                      const char *suite, int argc, char **argv)
{
    int failures = 0;
    const char *filter = argc > 1 ? argv[1] : NULL;
    size_t ran = 0;

    if (filter != NULL && strcmp(filter, "--hashes") == 0) {
        for (size_t i = 0; i < count; i++) {
            uint64_t sh = 0;
            (void)run_once(&table[i], seeds[0], NULL, &sh);
            printf("%-32s 0x%016llx%s\n", table[i].name,
                   (unsigned long long)sh,
                   table[i].deterministic ? "" : " (nondet)");
        }
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        if (filter != NULL && strcmp(filter, table[i].name) != 0)
            continue;
        int f = run_scenario(&table[i], seeds, nseeds);
        if (f > 0)
            fprintf(stderr, "FAIL scenario %s (%d)\n", table[i].name, f);
        failures += f;
        ran++;
    }
    if (filter != NULL && ran == 0) {
        fprintf(stderr, "no scenario named '%s'\n", filter);
        return 2;
    }
    if (failures > 0) {
        fprintf(stderr, "FAILED: %s (%d across %zu scenarios)\n", suite,
                failures, ran);
        return 1;
    }
    printf("PASS: %s (%zu scenarios x %zu seeds)\n", suite, ran, nseeds);
    return 0;
}
