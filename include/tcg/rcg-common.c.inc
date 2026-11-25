/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * What RCG's translators share, whatever the guest. A front end includes
 * this after the table its rcg-gen.py generates, which defines
 * RCG_MAX_WORDS, RCGGadget and rcg_word_narrow() (see rcg_core.py's
 * write_table_head() and write_gadget_type()).
 */

/*
 * Adds g to list unless it is already there. Each list has room for
 * RCG_MAX_WORDS.
 */
static inline void rcg_note_temp(TCGTemp **list, unsigned *n, TCGTemp *g)
{
    for (unsigned i = 0; i < *n; i++) {
        if (list[i] == g) {
            return;
        }
    }
    tcg_debug_assert(*n < RCG_MAX_WORDS);
    list[(*n)++] = g;
}

/*
 * Packs the words of g, a gadget that accesses memory, into stream words,
 * matching rcg_core.py's stream_words(): the narrow words two to a stream
 * word, the first in the low half, then the odd one out alone, then each
 * of the others alone. Returns how many stream words there are. Only the
 * RCG tests, which take every gadget (rcg-gen.py --coverage), check that
 * the two layouts agree.
 */
static inline unsigned rcg_pack_words(const RCGGadget *g, uint64_t *words,
                                      unsigned n)
{
    uint64_t out[RCG_MAX_WORDS];
    unsigned nb = 0, i;
    bool odd = false;

    for (i = 0; i < n; i++) {
        if (!rcg_word_narrow(g->words[i])) {
            continue;
        }
        tcg_debug_assert((int32_t)words[i] == (int64_t)words[i]);
        if (odd) {
            out[nb - 1] = deposit64(out[nb - 1], 32, 32, words[i]);
        } else {
            out[nb++] = words[i];
        }
        odd = !odd;
    }
    for (i = 0; i < n; i++) {
        if (!rcg_word_narrow(g->words[i])) {
            out[nb++] = words[i];
        }
    }
    memcpy(words, out, nb * sizeof(uint64_t));
    return nb;
}
