#ifndef LOCAL_FLUSH_ORACLE_H
#define LOCAL_FLUSH_ORACLE_H

#include <stdbool.h>

enum nf_result { NF_WAIT, NF_PASS, NF_INVALID, NF_COVERAGE_NOT_EXERCISED };
enum nf_flush { NF_FLUSH_OK, NF_FLUSH_PENDING, NF_FLUSH_LOSS, NF_FLUSH_INVALID };

struct nf_stream {
    const void *identity;
    unsigned accepted, returned, canceled, borrows;
    unsigned shutdowns, graceful, abortive, commits;
    bool fin_submitted, intent_accepted, decision;
};

/* These predicates judge observations, never drive provider/application work. */
static inline enum nf_result nf_canceled(const struct nf_stream *st,
    const void *identity, bool intentional, enum nf_flush flush)
{
    if (!identity || st->identity != identity || st->accepted > 1 ||
        st->returned > st->accepted || st->canceled > st->returned ||
        st->shutdowns > 1 || st->graceful + st->abortive != st->shutdowns ||
        st->commits != 0 || (flush != NF_FLUSH_OK &&
        flush != NF_FLUSH_PENDING && flush != NF_FLUSH_LOSS))
        return NF_INVALID;
    if (st->decision) return NF_WAIT;
    if (st->intent_accepted != intentional) {
        if (st->accepted || st->returned || st->shutdowns) return NF_INVALID;
        return NF_WAIT;
    }
    if (intentional && flush == NF_FLUSH_LOSS) return NF_INVALID;
    if (!st->accepted || !st->returned || st->borrows || !st->shutdowns)
        return NF_WAIT;
    if (!st->fin_submitted) return NF_INVALID;
    if (st->canceled != 1) return NF_COVERAGE_NOT_EXERCISED;
    if (flush == NF_FLUSH_PENDING) return NF_WAIT;
    return flush == (intentional ? NF_FLUSH_OK : NF_FLUSH_LOSS) ?
        NF_PASS : NF_INVALID;
}

static inline enum nf_result nf_replacement(const struct nf_stream *old,
    const void *old_identity, const struct nf_stream *next,
    const void *next_identity, enum nf_flush flush)
{
    /* Old ownership was already fenced before the new stream was opened. */
    enum nf_result prior = nf_canceled(old, old_identity, true, NF_FLUSH_OK);
    if (prior != NF_PASS) return NF_INVALID;
    if (!next_identity || next_identity == old_identity ||
        next->identity != next_identity || next->accepted > 1 ||
        next->returned > next->accepted || next->canceled ||
        next->shutdowns > 1 || next->graceful + next->abortive != next->shutdowns ||
        next->abortive || next->commits > 1 || next->intent_accepted ||
        next->decision || (flush != NF_FLUSH_OK && flush != NF_FLUSH_PENDING))
        return NF_INVALID;
    if (!next->accepted || !next->returned || next->borrows ||
        !next->shutdowns || !next->commits) return NF_WAIT;
    if (!next->fin_submitted) return NF_INVALID;
    return flush == NF_FLUSH_OK ? NF_PASS : NF_WAIT;
}

#endif
