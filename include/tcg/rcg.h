/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * RCG, the rich code generator: under TCTI, a guest instruction the front
 * end has a gadget for runs as that one gadget rather than as a gadget for
 * each of its TCG ops. -accel tcg,rcg=on|off turns it on or off. It is off
 * by default, and never active while native code runs (the hybrid's JIT),
 * as the gadgets exist only for TCTI's streams.
 *
 * tcg_rcg_active() is a constant false in builds that cannot run TCTI, so
 * a test of it costs nothing there.
 */

#ifndef TCG_RCG_H
#define TCG_RCG_H

#include "tcg/hybrid.h"

#ifdef TCG_HAVE_TCTI
#define TCG_HAVE_RCG 1

/* Set once, from -accel tcg,rcg=, before any translation. */
extern bool tcg_rcg_enabled;

/*
 * Whether to translate with RCG. In the hybrid this changes when the
 * backend switches, which flushes every TB first. Test it only while
 * translating, and never keep the answer past the TB.
 */
#define tcg_rcg_active()  (tcg_rcg_enabled && tcg_tcti_active())
#else
#define tcg_rcg_active()  false
#endif

#endif /* TCG_RCG_H */
