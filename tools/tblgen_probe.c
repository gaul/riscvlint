// tblgen_probe: the set of compressed forms riscvlint's own decoders
// claim a four-byte instruction can take, derived by asking them about
// every encoding there is.
//
// tools/tblgen_audit.py diffs this against LLVM's CompressPat records,
// which are the assembler's actual rules. A form LLVM can produce and
// this never names is a rule riscvlint does not model -- a false
// negative in check_c_compressible or check_zcb_compressible, which
// between them are 59% of the corpus's findings. A form this names and
// LLVM has no rule for is worse: advice that will not assemble.
//
// Enumerating rather than pattern-matching is the point. riscvlint's
// claims live in C control flow, not in a table that can be read off,
// so the only honest way to ask "which forms can it name" is to try
// every word. There are 2^30 of them and it takes seconds.
//
//     make tools && ./tools/tblgen_probe

#include "../riscvlint.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FORMS 64
#define NAME_MAX  24

typedef struct {
    char name[NAME_MAX];
    uint64_t count;
    uint32_t example;
} form;

typedef struct {
    // 64-bit, because the exclusive end of the four-byte space is 2^32
    // and a uint32_t holds that as 0 -- which silently gave the last
    // worker an empty range and left a sixteenth of the space unread.
    // The audit in tools/tblgen_audit.py is what caught it: `c.not`
    // came back as a form riscvlint never names, and riscvlint names it
    // only at 0xfff4_4413 and up.
    uint64_t lo, hi;
    form forms[MAX_FORMS];
    unsigned nforms;
    uint64_t decoded;
    bool overflowed;
} job;

static void note(job *j, const char *name, uint32_t w)
{
    for (unsigned i = 0; i < j->nforms; i++)
        if (!strcmp(j->forms[i].name, name)) {
            j->forms[i].count++;
            return;
        }
    if (j->nforms == MAX_FORMS) { j->overflowed = true; return; }
    snprintf(j->forms[j->nforms].name, NAME_MAX, "%s", name);
    j->forms[j->nforms].count = 1;
    j->forms[j->nforms].example = w;
    j->nforms++;
}

static void run(job *j)
{
    for (uint64_t v = j->lo; v < j->hi; v++) {
        uint32_t w = (uint32_t)v;
        // Four-byte encodings only: both low bits set.
        if ((w & 3u) != 3u) continue;
        j->decoded++;
        char buf[NAME_MAX];
        if (rv_c_form(w, 4, buf, sizeof buf)) note(j, buf, w);
        const char *z = rv_zcb_form(w, 4);
        if (z) note(j, z, w);
    }
}

static void *thread_main(void *arg)
{
    run(arg);
    return NULL;
}

static int cmp_form(const void *a, const void *b)
{
    return strcmp(((const form *)a)->name, ((const form *)b)->name);
}

int main(int argc, char **argv)
{
    unsigned nthreads = 8;
    if (argc > 1) {
        long v = strtol(argv[1], NULL, 10);
        if (v > 0 && v <= 64) nthreads = (unsigned)v;
    }
    job *jobs = calloc(nthreads, sizeof *jobs);
    pthread_t *tids = calloc(nthreads, sizeof *tids);
    if (!jobs || !tids) return 2;
    uint64_t span = 0x100000000ull / nthreads;
    for (unsigned i = 0; i < nthreads; i++) {
        jobs[i].lo = i * span;
        jobs[i].hi = i + 1 == nthreads ? 0x100000000ull : (i + 1) * span;
    }
    unsigned started = 0;
    for (unsigned i = 0; i < nthreads; i++)
        if (pthread_create(&tids[i], NULL, thread_main, &jobs[i]) == 0)
            started++;
        else
            break;
    // A worker that would not start is run here, so the enumeration is
    // never reported as complete over a range nothing read.
    for (unsigned i = started; i < nthreads; i++) run(&jobs[i]);
    for (unsigned i = 0; i < started; i++) pthread_join(tids[i], NULL);

    form all[MAX_FORMS];
    unsigned n = 0;
    uint64_t decoded = 0;
    bool overflowed = false;
    for (unsigned i = 0; i < nthreads; i++) {
        decoded += jobs[i].decoded;
        overflowed |= jobs[i].overflowed;
        for (unsigned k = 0; k < jobs[i].nforms; k++) {
            unsigned j = 0;
            while (j < n && strcmp(all[j].name, jobs[i].forms[k].name)) j++;
            if (j == n) {
                if (n == MAX_FORMS) { overflowed = true; continue; }
                all[n++] = jobs[i].forms[k];
            } else {
                all[j].count += jobs[i].forms[k].count;
            }
        }
    }
    qsort(all, n, sizeof all[0], cmp_form);

    printf("# riscvlint compressed forms, over %" PRIu64 " four-byte words\n",
           decoded);
    printf("# form  words-that-claim-it  example-encoding\n");
    for (unsigned i = 0; i < n; i++)
        printf("%s %" PRIu64 " 0x%08x\n", all[i].name, all[i].count,
               all[i].example);
    if (overflowed)
        printf("# note: more than %d distinct forms; the list is partial\n",
               MAX_FORMS);
    free(jobs);
    free(tids);
    return 0;
}
