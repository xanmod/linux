// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2022 Linutronix GmbH, John Ogness
// Copyright (C) 2022 Intel, Thomas Gleixner

#include <linux/kernel.h>
#include <linux/console.h>
#include "internal.h"
/*
 * Printk implementation for consoles that do not depend on the BKL style
 * console_lock mechanism.
 *
 * Console is locked on a CPU when state::locked is set and state:cpu ==
 * current CPU. This is valid for the current execution context.
 *
 * Nesting execution contexts on the same CPU can carefully take over
 * if the driver allows reentrancy via state::unsafe = false. When the
 * interrupted context resumes it checks the state before entering
 * an unsafe region and aborts the operation if it detects a takeover.
 *
 * In case of panic or emergency the nesting context can take over the
 * console forcefully. The write callback is then invoked with the unsafe
 * flag set in the write context data, which allows the driver side to avoid
 * locks and to evaluate the driver state so it can use an emergency path
 * or repair the state instead of blindly assuming that it works.
 *
 * If the interrupted context touches the assigned record buffer after
 * takeover, it does not cause harm because at the same execution level
 * there is no concurrency on the same CPU. A threaded printer always has
 * its own record buffer so it can never interfere with any of the per CPU
 * record buffers.
 *
 * A concurrent writer on a different CPU can request to take over the
 * console by:
 *
 *	1) Carefully writing the desired state into state[REQ]
 *	   if there is no same or higher priority request pending.
 *	   This locks state[REQ] except for higher priority
 *	   waiters.
 *
 *	2) Setting state[CUR].req_prio unless a same or higher
 *	   priority waiter won the race.
 *
 *	3) Carefully spin on state[CUR] until that is locked with the
 *	   expected state. When the state is not the expected one then it
 *	   has to verify that state[REQ] is still the same and that
 *	   state[CUR] has not been taken over or unlocked.
 *
 *      The unlocker hands over to state[REQ], but only if state[CUR]
 *	matches.
 *
 * In case that the owner does not react on the request and does not make
 * observable progress, the waiter will timeout and can then decide to do
 * a hostile takeover.
 */

#define copy_full_state(_dst, _src)	do { _dst = _src; } while (0)
#define copy_bit_state(_dst, _src)	do { _dst.bits = _src.bits; } while (0)

#ifdef CONFIG_64BIT
#define copy_seq_state64(_dst, _src)	do { _dst.seq = _src.seq; } while (0)
#else
#define copy_seq_state64(_dst, _src)	do { } while (0)
#endif

enum state_selector {
	CON_STATE_CUR,
	CON_STATE_REQ,
};

/**
 * cons_state_set - Helper function to set the console state
 * @con:	Console to update
 * @which:	Selects real state or handover state
 * @new:	The new state to write
 *
 * Only to be used when the console is not yet or no longer visible in the
 * system. Otherwise use cons_state_try_cmpxchg().
 */
static inline void cons_state_set(struct console *con, enum state_selector which,
				  struct cons_state *new)
{
	atomic_long_set(&ACCESS_PRIVATE(con, atomic_state[which]), new->atom);
}

/**
 * cons_state_read - Helper function to read the console state
 * @con:	Console to update
 * @which:	Selects real state or handover state
 * @state:	The state to store the result
 */
static inline void cons_state_read(struct console *con, enum state_selector which,
				   struct cons_state *state)
{
	state->atom = atomic_long_read(&ACCESS_PRIVATE(con, atomic_state[which]));
}

/**
 * cons_state_try_cmpxchg() - Helper function for atomic_long_try_cmpxchg() on console state
 * @con:	Console to update
 * @which:	Selects real state or handover state
 * @old:	Old/expected state
 * @new:	New state
 *
 * Returns: True on success, false on fail
 */
static inline bool cons_state_try_cmpxchg(struct console *con,
					  enum state_selector which,
					  struct cons_state *old,
					  struct cons_state *new)
{
	return atomic_long_try_cmpxchg(&ACCESS_PRIVATE(con, atomic_state[which]),
				       &old->atom, new->atom);
}

/**
 * cons_nobkl_init - Initialize the NOBKL console specific data
 * @con:	Console to initialize
 */
void cons_nobkl_init(struct console *con)
{
	struct cons_state state = { };

	cons_state_set(con, CON_STATE_CUR, &state);
	cons_state_set(con, CON_STATE_REQ, &state);
}

/**
 * cons_nobkl_cleanup - Cleanup the NOBKL console specific data
 * @con:	Console to cleanup
 */
void cons_nobkl_cleanup(struct console *con)
{
	struct cons_state state = { };

	cons_state_set(con, CON_STATE_CUR, &state);
	cons_state_set(con, CON_STATE_REQ, &state);
}
