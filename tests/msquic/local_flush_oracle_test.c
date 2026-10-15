#include "local_flush_oracle.h"
#include <stdio.h>
#include <string.h>

static int failures;
static unsigned cases;

static void check(const char *name, enum nf_result actual, enum nf_result want)
{
    ++cases;
    if (actual != want) {
        fprintf(stderr, "FAIL %s: got %d expected %d\n", name, actual, want);
        ++failures;
    }
}

int main(int argc, char **argv)
{
    static const int old_identity = 1, next_identity = 2, wrong_identity = 3;
    struct nf_stream old = { .identity = &old_identity, .accepted = 1,
        .returned = 1, .canceled = 1, .shutdowns = 1, .graceful = 1,
        .fin_submitted = true, .intent_accepted = true };
    struct nf_stream next = { .identity = &next_identity, .accepted = 1,
        .returned = 1, .shutdowns = 1, .graceful = 1, .commits = 1,
        .fin_submitted = true };
    if (argc == 2 && strcmp(argv[1], "--original-abortive-oracle") == 0) {
        /* Deliberately RED: the original rule rejects this legal observation. */
        check("original_rejects_canceled_graceful",
            old.abortive == 1 ? NF_PASS : NF_INVALID, NF_PASS);
        return failures ? 1 : 0;
    }
    if (argc != 1) return 2;
    check("canceled_graceful", nf_canceled(&old, &old_identity, true, NF_FLUSH_OK), NF_PASS);
    struct nf_stream changed = old;
    changed.graceful = 0; changed.abortive = 1;
    check("canceled_abortive", nf_canceled(&changed, &old_identity, true, NF_FLUSH_OK), NF_PASS);
    changed = old; changed.intent_accepted = false;
    check("missing_intent", nf_canceled(&changed, &old_identity, true, NF_FLUSH_OK), NF_INVALID);
    check("unexpected_loss", nf_canceled(&changed, &old_identity, false, NF_FLUSH_LOSS), NF_PASS);
    check("unexpected_not_sticky", nf_canceled(&changed, &old_identity, false, NF_FLUSH_OK), NF_INVALID);
    changed = old; changed.borrows = 1;
    check("retained_borrow", nf_canceled(&changed, &old_identity, true, NF_FLUSH_OK), NF_WAIT);
    changed = old; changed.shutdowns = changed.graceful = 0;
    check("absent_shutdown", nf_canceled(&changed, &old_identity, true, NF_FLUSH_OK), NF_WAIT);
    changed = old; changed.shutdowns = changed.graceful = 2;
    check("duplicate_shutdown", nf_canceled(&changed, &old_identity, true, NF_FLUSH_OK), NF_INVALID);
    changed = old; changed.commits = 1;
    check("old_false_commit", nf_canceled(&changed, &old_identity, true, NF_FLUSH_OK), NF_INVALID);
    changed = old; changed.canceled = 0;
    check("missing_cancellation", nf_canceled(&changed, &old_identity, true, NF_FLUSH_OK), NF_COVERAGE_NOT_EXERCISED);
    changed = old; changed.returned = changed.canceled = 0;
    check("missing_return", nf_canceled(&changed, &old_identity, true, NF_FLUSH_OK), NF_WAIT);
    changed = old; changed.decision = true;
    check("decision_pending", nf_canceled(&changed, &old_identity, true, NF_FLUSH_OK), NF_WAIT);
    check("old_wrong_identity", nf_canceled(&old, &wrong_identity, true, NF_FLUSH_OK), NF_INVALID);
    check("old_loss", nf_canceled(&old, &old_identity, true, NF_FLUSH_LOSS), NF_INVALID);
    check("old_pending", nf_canceled(&old, &old_identity, true, NF_FLUSH_PENDING), NF_WAIT);
    check("old_closed_or_state", nf_canceled(&old, &old_identity, true, NF_FLUSH_INVALID), NF_INVALID);
    check("replacement", nf_replacement(&old, &old_identity, &next, &next_identity, NF_FLUSH_OK), NF_PASS);
    changed = next; changed.identity = &wrong_identity;
    check("wrong_replacement_identity", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_INVALID);
    changed = next; changed.commits = 0;
    check("missing_replacement_commit", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_WAIT);
    changed = next; changed.fin_submitted = false;
    check("missing_replacement_fin", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_INVALID);
    changed = next; changed.graceful = 0; changed.abortive = 1;
    check("replacement_abortive", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_INVALID);
    changed = next; changed.borrows = 1;
    check("replacement_borrow", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_WAIT);
    changed = next; changed.shutdowns = changed.graceful = 0;
    check("replacement_missing_shutdown", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_WAIT);
    changed = next; changed.shutdowns = changed.graceful = 2;
    check("replacement_duplicate_shutdown", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_INVALID);
    changed = next; changed.commits = 2;
    check("replacement_duplicate_commit", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_INVALID);
    changed = next; changed.returned = 0;
    check("replacement_missing_return", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_WAIT);
    changed = next; changed.canceled = 1;
    check("replacement_canceled", nf_replacement(&old, &old_identity, &changed, &next_identity, NF_FLUSH_OK), NF_INVALID);
    check("replacement_bad_flush", nf_replacement(&old, &old_identity, &next, &next_identity, NF_FLUSH_LOSS), NF_INVALID);
    check("replacement_pending", nf_replacement(&old, &old_identity, &next, &next_identity, NF_FLUSH_PENDING), NF_WAIT);
    check("replacement_unknown_flush", nf_replacement(&old, &old_identity, &next, &next_identity, (enum nf_flush)99), NF_INVALID);
    check("replacement_aliases_old", nf_replacement(&old, &old_identity, &next, &old_identity, NF_FLUSH_OK), NF_INVALID);
    changed = old; changed.commits = 1;
    check("wrong_stream_commit", nf_replacement(&changed, &old_identity, &next, &next_identity, NF_FLUSH_OK), NF_INVALID);
    changed = old; changed.borrows = 1;
    check("replacement_before_old_settlement", nf_replacement(&changed, &old_identity, &next, &next_identity, NF_FLUSH_OK), NF_INVALID);
    printf("native oracle: %u cases, %d failures\n", cases, failures);
    return failures ? 1 : 0;
}
