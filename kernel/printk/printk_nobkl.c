// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2022 Linutronix GmbH, John Ogness
// Copyright (C) 2022 Intel, Thomas Gleixner

#include <linux/kernel.h>
#include <linux/console.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/syscore_ops.h>
#include "printk_ringbuffer.h"
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
 * cons_state_full_match - Check whether the full state matches
 * @cur:	The state to check
 * @prev:	The previous state
 *
 * Returns: True if matching, false otherwise.
 *
 * Check the full state including state::seq on 64bit. For take over
 * detection.
 */
static inline bool cons_state_full_match(struct cons_state cur,
					 struct cons_state prev)
{
	/*
	 * req_prio can be set by a concurrent writer for friendly
	 * handover. Ignore it in the comparison.
	 */
	cur.req_prio = prev.req_prio;
	return cur.atom == prev.atom;
}

/**
 * cons_state_bits_match - Check for matching state bits
 * @cur:	The state to check
 * @prev:	The previous state
 *
 * Returns: True if state matches, false otherwise.
 *
 * Contrary to cons_state_full_match this checks only the bits and ignores
 * a sequence change on 64bits. On 32bit the two functions are identical.
 */
static inline bool cons_state_bits_match(struct cons_state cur, struct cons_state prev)
{
	/*
	 * req_prio can be set by a concurrent writer for friendly
	 * handover. Ignore it in the comparison.
	 */
	cur.req_prio = prev.req_prio;
	return cur.bits == prev.bits;
}

/**
 * cons_check_panic - Check whether a remote CPU is in panic
 *
 * Returns: True if a remote CPU is in panic, false otherwise.
 */
static inline bool cons_check_panic(void)
{
	unsigned int pcpu = atomic_read(&panic_cpu);

	return pcpu != PANIC_CPU_INVALID && pcpu != smp_processor_id();
}

static struct cons_context_data early_cons_ctxt_data __initdata;

/**
 * cons_context_set_pbufs - Set the output text buffer for the current context
 * @ctxt:	Pointer to the acquire context
 *
 * Buffer selection:
 *   1) Early boot uses the global (initdata) buffer
 *   2) Printer threads use the dynamically allocated per-console buffers
 *   3) All other contexts use the per CPU buffers
 *
 * This guarantees that there is no concurrency on the output records ever.
 * Early boot and per CPU nesting is not a problem. The takeover logic
 * tells the interrupted context that the buffer has been overwritten.
 *
 * There are two critical regions that matter:
 *
 * 1) Context is filling the buffer with a record. After interruption
 *    it continues to sprintf() the record and before it goes to
 *    write it out, it checks the state, notices the takeover, discards
 *    the content and backs out.
 *
 * 2) Context is in a unsafe critical region in the driver. After
 *    interruption it might read overwritten data from the output
 *    buffer. When it leaves the critical region it notices and backs
 *    out. Hostile takeovers in driver critical regions are best effort
 *    and there is not much that can be done about that.
 */
static __ref void cons_context_set_pbufs(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;

	/* Thread context or early boot? */
	if (ctxt->thread)
		ctxt->pbufs = con->thread_pbufs;
	else if (!con->pcpu_data)
		ctxt->pbufs = &early_cons_ctxt_data.pbufs;
	else
		ctxt->pbufs = &(this_cpu_ptr(con->pcpu_data)->pbufs);
}

/**
 * cons_seq_init - Helper function to initialize the console sequence
 * @con:	Console to work on
 *
 * Set @con->atomic_seq to the starting record, or if that record no
 * longer exists, the oldest available record. For init only. Do not
 * use for runtime updates.
 */
static void cons_seq_init(struct console *con)
{
	u32 seq = (u32)max_t(u64, con->seq, prb_first_valid_seq(prb));
#ifdef CONFIG_64BIT
	struct cons_state state;

	cons_state_read(con, CON_STATE_CUR, &state);
	state.seq = seq;
	cons_state_set(con, CON_STATE_CUR, &state);
#else
	atomic_set(&ACCESS_PRIVATE(con, atomic_seq), seq);
#endif
}

/**
 * cons_force_seq - Force a specified sequence number for a console
 * @con:	Console to work on
 * @seq:	Sequence number to force
 *
 * This function is only intended to be used in emergency situations. In
 * particular: console_flush_on_panic(CONSOLE_REPLAY_ALL)
 */
void cons_force_seq(struct console *con, u64 seq)
{
#ifdef CONFIG_64BIT
	struct cons_state old;
	struct cons_state new;

	do {
		cons_state_read(con, CON_STATE_CUR, &old);
		copy_bit_state(new, old);
		new.seq = seq;
	} while (!cons_state_try_cmpxchg(con, CON_STATE_CUR, &old, &new));
#else
	atomic_set(&ACCESS_PRIVATE(con, atomic_seq), seq);
#endif
}

static inline u64 cons_expand_seq(u64 seq)
{
	u64 rbseq;

	/*
	 * The provided sequence is only the lower 32bits of the ringbuffer
	 * sequence. It needs to be expanded to 64bit. Get the next sequence
	 * number from the ringbuffer and fold it.
	 */
	rbseq = prb_next_seq(prb);
	seq = rbseq - ((u32)rbseq - (u32)seq);

	return seq;
}

/**
 * cons_read_seq - Read the current console sequence
 * @con:	Console to read the sequence of
 *
 * Returns:	Sequence number of the next record to print on @con.
 */
u64 cons_read_seq(struct console *con)
{
	u64 seq;
#ifdef CONFIG_64BIT
	struct cons_state state;

	cons_state_read(con, CON_STATE_CUR, &state);
	seq = state.seq;
#else
	seq = atomic_read(&ACCESS_PRIVATE(con, atomic_seq));
#endif
	return cons_expand_seq(seq);
}

/**
 * cons_context_set_seq - Setup the context with the next sequence to print
 * @ctxt:	Pointer to an acquire context that contains
 *		all information about the acquire mode
 *
 * On return the retrieved sequence number is stored in ctxt->oldseq.
 *
 * The sequence number is safe in forceful takeover situations.
 *
 * Either the writer succeeded to update before it got interrupted
 * or it failed. In the latter case the takeover will print the
 * same line again.
 *
 * The sequence is only the lower 32bits of the ringbuffer sequence. The
 * ringbuffer must be 2^31 records ahead to get out of sync. This needs
 * some care when starting a console, i.e setting the sequence to 0 is
 * wrong. It has to be set to the oldest valid sequence in the ringbuffer
 * as that cannot be more than 2^31 records away
 *
 * On 64bit the 32bit sequence is part of console::state, which is saved
 * in @ctxt->state. This prevents the 32bit update race.
 */
static void cons_context_set_seq(struct cons_context *ctxt)
{
#ifdef CONFIG_64BIT
	ctxt->oldseq = ctxt->state.seq;
#else
	ctxt->oldseq = atomic_read(&ACCESS_PRIVATE(ctxt->console, atomic_seq));
#endif
	ctxt->oldseq = cons_expand_seq(ctxt->oldseq);
	ctxt->newseq = ctxt->oldseq;
}

/**
 * cons_seq_try_update - Try to update the console sequence number
 * @ctxt:	Pointer to an acquire context that contains
 *		all information about the acquire mode
 *
 * Returns:	True if the console sequence was updated, false otherwise.
 *
 * Internal helper as the logic is different on 32bit and 64bit.
 *
 * On 32 bit the sequence is separate from state and therefore
 * subject to a subtle race in the case of hostile takeovers.
 *
 * On 64 bit the sequence is part of the state and therefore safe
 * vs. hostile takeovers.
 *
 * In case of fail the console has been taken over and @ctxt is
 * invalid. Caller has to reacquire the console.
 */
#ifdef CONFIG_64BIT
static bool cons_seq_try_update(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	struct cons_state old;
	struct cons_state new;

	cons_state_read(con, CON_STATE_CUR, &old);
	do {
		/* Make sure this context is still the owner. */
		if (!cons_state_bits_match(old, ctxt->state))
			return false;

		/* Preserve bit state */
		copy_bit_state(new, old);
		new.seq = ctxt->newseq;

		/*
		 * Can race with hostile takeover or with a handover
		 * request.
		 */
	} while (!cons_state_try_cmpxchg(con, CON_STATE_CUR, &old, &new));

	copy_full_state(ctxt->state, new);
	ctxt->oldseq = ctxt->newseq;

	return true;
}
#else
static bool cons_release(struct cons_context *ctxt);
static bool cons_seq_try_update(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	struct cons_state state;
	int pcpu;
	u32 old;
	u32 new;

	/*
	 * There is a corner case that needs to be considered here:
	 *
	 * CPU0			CPU1
	 * printk()
	 *  acquire()		-> emergency
	 *  write()		   acquire()
	 *  update_seq()
	 *    state == OK
	 * --> NMI
	 *			   takeover()
	 * <---			     write()
	 *  cmpxchg() succeeds	     update_seq()
	 *			     cmpxchg() fails
	 *
	 * There is nothing that can be done about this other than having
	 * yet another state bit that needs to be tracked and analyzed,
	 * but fails to cover the problem completely.
	 *
	 * No other scenarios expose such a problem. On same CPU takeovers
	 * the cmpxchg() always fails on the interrupted context after the
	 * interrupting context finished printing, but that's fine as it
	 * does not own the console anymore. The state check after the
	 * failed cmpxchg prevents that.
	 */
	cons_state_read(con, CON_STATE_CUR, &state);
	/* Make sure this context is still the owner. */
	if (!cons_state_bits_match(state, ctxt->state))
		return false;

	/*
	 * Get the original sequence number that was retrieved
	 * from @con->atomic_seq. @con->atomic_seq should be still
	 * the same. 32bit truncates. See cons_context_set_seq().
	 */
	old = (u32)ctxt->oldseq;
	new = (u32)ctxt->newseq;
	if (atomic_try_cmpxchg(&ACCESS_PRIVATE(con, atomic_seq), &old, new)) {
		ctxt->oldseq = ctxt->newseq;
		return true;
	}

	/*
	 * Reread the state. If this context does not own the console anymore
	 * then it cannot touch the sequence again.
	 */
	cons_state_read(con, CON_STATE_CUR, &state);
	if (!cons_state_bits_match(state, ctxt->state))
		return false;

	pcpu = atomic_read(&panic_cpu);
	if (pcpu == smp_processor_id()) {
		/*
		 * This is the panic CPU. Emitting a warning here does not
		 * help at all. The callchain is clear and the priority is
		 * to get the messages out. In the worst case duplicated
		 * ones. That's a job for postprocessing.
		 */
		atomic_set(&ACCESS_PRIVATE(con, atomic_seq), new);
		ctxt->oldseq = ctxt->newseq;
		return true;
	}

	/*
	 * Only emit a warning when this happens outside of a panic
	 * situation as on panic it's neither useful nor helping to let the
	 * panic CPU get the important stuff out.
	 */
	WARN_ON_ONCE(pcpu == PANIC_CPU_INVALID);

	cons_release(ctxt);
	return false;
}
#endif

/**
 * cons_cleanup_handover - Cleanup a handover request
 * @ctxt:	Pointer to acquire context
 *
 * @ctxt->hov_state contains the state to clean up
 */
static void cons_cleanup_handover(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	struct cons_state new;

	/*
	 * No loop required. Either hov_state is still the same or
	 * not.
	 */
	new.atom = 0;
	cons_state_try_cmpxchg(con, CON_STATE_REQ, &ctxt->hov_state, &new);
}

/**
 * cons_setup_handover - Setup a handover request
 * @ctxt:	Pointer to acquire context
 *
 * Returns: True if a handover request was setup, false otherwise.
 *
 * On success @ctxt->hov_state contains the requested handover state
 *
 * On failure this context is not allowed to request a handover from the
 * current owner. Reasons would be priority too low or a remote CPU in panic.
 * In both cases this context should give up trying to acquire the console.
 */
static bool cons_setup_handover(struct cons_context *ctxt)
{
	unsigned int cpu = smp_processor_id();
	struct console *con = ctxt->console;
	struct cons_state old;
	struct cons_state hstate = {
		.locked		= 1,
		.cur_prio	= ctxt->prio,
		.cpu		= cpu,
	};

	/*
	 * Try to store hstate in @con->atomic_state[REQ]. This might
	 * race with a higher priority waiter.
	 */
	cons_state_read(con, CON_STATE_REQ, &old);
	do {
		if (cons_check_panic())
			return false;

		/* Same or higher priority waiter exists? */
		if (old.cur_prio >= ctxt->prio)
			return false;

	} while (!cons_state_try_cmpxchg(con, CON_STATE_REQ, &old, &hstate));

	/* Save that state for comparison in spinwait */
	copy_full_state(ctxt->hov_state, hstate);
	return true;
}

/**
 * cons_setup_request - Setup a handover request in state[CUR]
 * @ctxt:	Pointer to acquire context
 * @old:	The state that was used to make the decision to spin wait
 *
 * Returns: True if a handover request was setup in state[CUR], false
 * otherwise.
 *
 * On success @ctxt->req_state contains the request state that was set in
 * state[CUR]
 *
 * On failure this context encountered unexpected state values. This
 * context should retry the full handover request setup process (the
 * handover request setup by cons_setup_handover() is now invalidated
 * and must be performed again).
 */
static bool cons_setup_request(struct cons_context *ctxt, struct cons_state old)
{
	struct console *con = ctxt->console;
	struct cons_state cur;
	struct cons_state new;

	/* Now set the request in state[CUR] */
	cons_state_read(con, CON_STATE_CUR, &cur);
	do {
		if (cons_check_panic())
			goto cleanup;

		/* Bit state changed vs. the decision to spinwait? */
		if (!cons_state_bits_match(cur, old))
			goto cleanup;

		/*
		 * A higher or equal priority context already setup a
		 * request?
		 */
		if (cur.req_prio >= ctxt->prio)
			goto cleanup;

		/* Setup a request for handover. */
		copy_full_state(new, cur);
		new.req_prio = ctxt->prio;
	} while (!cons_state_try_cmpxchg(con, CON_STATE_CUR, &cur, &new));

	/* Save that state for comparison in spinwait */
	copy_bit_state(ctxt->req_state, new);
	return true;

cleanup:
	cons_cleanup_handover(ctxt);
	return false;
}

/**
 * cons_try_acquire_spin - Complete the spinwait attempt
 * @ctxt:	Pointer to an acquire context that contains
 *		all information about the acquire mode
 *
 * @ctxt->hov_state contains the handover state that was set in
 * state[REQ]
 * @ctxt->req_state contains the request state that was set in
 * state[CUR]
 *
 * Returns: 0 if successfully locked. -EBUSY on timeout. -EAGAIN on
 * unexpected state values.
 *
 * On success @ctxt->state contains the new state that was set in
 * state[CUR]
 *
 * On -EBUSY failure this context timed out. This context should either
 * give up or attempt a hostile takeover.
 *
 * On -EAGAIN failure this context encountered unexpected state values.
 * This context should retry the full handover request setup process (the
 * handover request setup by cons_setup_handover() is now invalidated and
 * must be performed again).
 */
static int cons_try_acquire_spin(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	struct cons_state cur;
	struct cons_state new;
	int err = -EAGAIN;
	int timeout;

	/* Now wait for the other side to hand over */
	for (timeout = ctxt->spinwait_max_us; timeout >= 0; timeout--) {
		/* Timeout immediately if a remote panic is detected. */
		if (cons_check_panic())
			break;

		cons_state_read(con, CON_STATE_CUR, &cur);

		/*
		 * If the real state of the console matches the handover state
		 * that this context setup, then the handover was a success
		 * and this context is now the owner.
		 *
		 * Note that this might have raced with a new higher priority
		 * requester coming in after the lock was handed over.
		 * However, that requester will see that the owner changes and
		 * setup a new request for the current owner (this context).
		 */
		if (cons_state_bits_match(cur, ctxt->hov_state))
			goto success;

		/*
		 * If state changed since the request was made, give up as
		 * it is no longer consistent. This must include
		 * state::req_prio since there could be a higher priority
		 * request available.
		 */
		if (cur.bits != ctxt->req_state.bits)
			goto cleanup;

		/*
		 * Finally check whether the handover state is still
		 * the same.
		 */
		cons_state_read(con, CON_STATE_REQ, &cur);
		if (cur.atom != ctxt->hov_state.atom)
			goto cleanup;

		/* Account time */
		if (timeout > 0)
			udelay(1);
	}

	/*
	 * Timeout. Cleanup the handover state and carefully try to reset
	 * req_prio in the real state. The reset is important to ensure
	 * that the owner does not hand over the lock after this context
	 * has given up waiting.
	 */
	cons_cleanup_handover(ctxt);

	cons_state_read(con, CON_STATE_CUR, &cur);
	do {
		/*
		 * The timeout might have raced with the owner coming late
		 * and handing it over gracefully.
		 */
		if (cons_state_bits_match(cur, ctxt->hov_state))
			goto success;

		/*
		 * Validate that the state matches with the state at request
		 * time. If this check fails, there is already a higher
		 * priority context waiting or the owner has changed (either
		 * by higher priority or by hostile takeover). In all fail
		 * cases this context is no longer in line for a handover to
		 * take place, so no reset is necessary.
		 */
		if (cur.bits != ctxt->req_state.bits)
			goto cleanup;

		copy_full_state(new, cur);
		new.req_prio = 0;
	} while (!cons_state_try_cmpxchg(con, CON_STATE_CUR, &cur, &new));
	/* Reset worked. Report timeout. */
	return -EBUSY;

success:
	/* Store the real state */
	copy_full_state(ctxt->state, cur);
	ctxt->hostile = false;
	err = 0;

cleanup:
	cons_cleanup_handover(ctxt);
	return err;
}

/**
 * __cons_try_acquire - Try to acquire the console for printk output
 * @ctxt:	Pointer to an acquire context that contains
 *		all information about the acquire mode
 *
 * Returns: True if the acquire was successful. False on fail.
 *
 * In case of success @ctxt->state contains the acquisition
 * state.
 *
 * In case of fail @ctxt->old_state contains the state
 * that was read from @con->state for analysis by the caller.
 */
static bool __cons_try_acquire(struct cons_context *ctxt)
{
	unsigned int cpu = smp_processor_id();
	struct console *con = ctxt->console;
	short flags = console_srcu_read_flags(con);
	struct cons_state old;
	struct cons_state new;
	int err;

	if (WARN_ON_ONCE(!(flags & CON_NO_BKL)))
		return false;
again:
	cons_state_read(con, CON_STATE_CUR, &old);

	/* Preserve it for the caller and for spinwait */
	copy_full_state(ctxt->old_state, old);

	if (cons_check_panic())
		return false;

	/* Set up the new state for takeover */
	copy_full_state(new, old);
	new.locked = 1;
	new.thread = ctxt->thread;
	new.cur_prio = ctxt->prio;
	new.req_prio = CONS_PRIO_NONE;
	new.cpu = cpu;

	/* Attempt to acquire it directly if unlocked */
	if (!old.locked) {
		if (!cons_state_try_cmpxchg(con, CON_STATE_CUR, &old, &new))
			goto again;

		ctxt->hostile = false;
		copy_full_state(ctxt->state, new);
		goto success;
	}

	/*
	 * A threaded printer context will never spin or perform a
	 * hostile takeover. The atomic writer will wake the thread
	 * when it is done with the important output.
	 */
	if (ctxt->thread)
		return false;

	/*
	 * If the active context is on the same CPU then there is
	 * obviously no handshake possible.
	 */
	if (old.cpu == cpu)
		goto check_hostile;

	/*
	 * If a handover request with same or higher priority is already
	 * pending then this context cannot setup a handover request.
	 */
	if (old.req_prio >= ctxt->prio)
		goto check_hostile;

	/*
	 * If the caller did not request spin-waiting then performing a
	 * handover is not an option.
	 */
	if (!ctxt->spinwait)
		goto check_hostile;

	/*
	 * Setup the request in state[REQ]. If this fails then this
	 * context is not allowed to setup a handover request.
	 */
	if (!cons_setup_handover(ctxt))
		goto check_hostile;

	/*
	 * Setup the request in state[CUR]. Hand in the state that was
	 * used to make the decision to spinwait above, for comparison. If
	 * this fails then unexpected state values were encountered and the
	 * full request setup process is retried.
	 */
	if (!cons_setup_request(ctxt, old))
		goto again;

	/*
	 * Spin-wait to acquire the console. If this fails then unexpected
	 * state values were encountered (for example, a hostile takeover by
	 * another context) and the full request setup process is retried.
	 */
	err = cons_try_acquire_spin(ctxt);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		goto check_hostile;
	}
success:
	/* Common updates on success */
	cons_context_set_seq(ctxt);
	cons_context_set_pbufs(ctxt);
	return true;

check_hostile:
	if (!ctxt->hostile)
		return false;

	if (cons_check_panic())
		return false;

	if (!cons_state_try_cmpxchg(con, CON_STATE_CUR, &old, &new))
		goto again;

	copy_full_state(ctxt->state, new);
	goto success;
}

/**
 * cons_try_acquire - Try to acquire the console for printk output
 * @ctxt:	Pointer to an acquire context that contains
 *		all information about the acquire mode
 *
 * Returns: True if the acquire was successful. False on fail.
 *
 * In case of success @ctxt->state contains the acquisition
 * state.
 *
 * In case of fail @ctxt->old_state contains the state
 * that was read from @con->state for analysis by the caller.
 */
static bool cons_try_acquire(struct cons_context *ctxt)
{
	if (__cons_try_acquire(ctxt))
		return true;

	ctxt->state.atom = 0;
	return false;
}

/**
 * __cons_release - Release the console after output is done
 * @ctxt:	The acquire context that contains the state
 *		at cons_try_acquire()
 *
 * Returns:	True if the release was regular
 *
 *		False if the console is in unusable state or was handed over
 *		with handshake or taken	over hostile without handshake.
 *
 * The return value tells the caller whether it needs to evaluate further
 * printing.
 */
static bool __cons_release(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	short flags = console_srcu_read_flags(con);
	struct cons_state hstate;
	struct cons_state old;
	struct cons_state new;

	if (WARN_ON_ONCE(!(flags & CON_NO_BKL)))
		return false;

	cons_state_read(con, CON_STATE_CUR, &old);
again:
	if (!cons_state_bits_match(old, ctxt->state))
		return false;

	/* Release it directly when no handover request is pending. */
	if (!old.req_prio)
		goto unlock;

	/* Read the handover target state */
	cons_state_read(con, CON_STATE_REQ, &hstate);

	/* If the waiter gave up hstate is 0 */
	if (!hstate.atom)
		goto unlock;

	/*
	 * If a higher priority waiter raced against a lower priority
	 * waiter then unlock instead of handing over to either. The
	 * higher priority waiter will notice the updated state and
	 * retry.
	 */
	if (hstate.cur_prio != old.req_prio)
		goto unlock;

	/* Switch the state and preserve the sequence on 64bit */
	copy_bit_state(new, hstate);
	copy_seq_state64(new, old);
	if (!cons_state_try_cmpxchg(con, CON_STATE_CUR, &old, &new))
		goto again;

	return true;

unlock:
	/* Clear the state and preserve the sequence on 64bit */
	new.atom = 0;
	copy_seq_state64(new, old);
	if (!cons_state_try_cmpxchg(con, CON_STATE_CUR, &old, &new))
		goto again;

	return true;
}

bool printk_threads_enabled __ro_after_init;
static bool printk_force_atomic __initdata;

/**
 * cons_release - Release the console after output is done
 * @ctxt:	The acquire context that contains the state
 *		at cons_try_acquire()
 *
 * Returns:	True if the release was regular
 *
 *		False if the console is in unusable state or was handed over
 *		with handshake or taken	over hostile without handshake.
 *
 * The return value tells the caller whether it needs to evaluate further
 * printing.
 */
static bool cons_release(struct cons_context *ctxt)
{
	bool ret = __cons_release(ctxt);

	/* Invalidate the buffer pointer. It is no longer valid. */
	ctxt->pbufs = NULL;

	ctxt->state.atom = 0;
	return ret;
}

bool console_try_acquire(struct cons_write_context *wctxt)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);

	return cons_try_acquire(ctxt);
}
EXPORT_SYMBOL_GPL(console_try_acquire);

bool console_release(struct cons_write_context *wctxt)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);

	return cons_release(ctxt);
}
EXPORT_SYMBOL_GPL(console_release);

/**
 * cons_alloc_percpu_data - Allocate percpu data for a console
 * @con:	Console to allocate for
 *
 * Returns: True on success. False otherwise and the console cannot be used.
 *
 * If it is not yet possible to allocate per CPU data, success is returned.
 * When per CPU data becomes possible, set_percpu_data_ready() will call
 * this function again for all registered consoles.
 */
bool cons_alloc_percpu_data(struct console *con)
{
	if (!printk_percpu_data_ready())
		return true;

	con->pcpu_data = alloc_percpu(typeof(*con->pcpu_data));
	if (con->pcpu_data)
		return true;

	con_printk(KERN_WARNING, con, "failed to allocate percpu buffers\n");
	return false;
}

/**
 * cons_free_percpu_data - Free percpu data of a console on unregister
 * @con:	Console to clean up
 */
static void cons_free_percpu_data(struct console *con)
{
	if (!con->pcpu_data)
		return;

	free_percpu(con->pcpu_data);
	con->pcpu_data = NULL;
}

/**
 * console_can_proceed - Check whether printing can proceed
 * @wctxt:	The write context that was handed to the write function
 *
 * Returns:	True if the state is correct. False if a handover
 *		has been requested or if the console was taken
 *		over.
 *
 * Must be invoked after the record was dumped into the assigned record
 * buffer and at appropriate safe places in the driver.  For unsafe driver
 * sections see console_enter_unsafe().
 *
 * When this function returns false then the calling context is not allowed
 * to go forward and has to back out immediately and carefully. The buffer
 * content is no longer trusted either and the console lock is no longer
 * held.
 */
bool console_can_proceed(struct cons_write_context *wctxt)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);
	struct console *con = ctxt->console;
	struct cons_state state;

	cons_state_read(con, CON_STATE_CUR, &state);
	/* Store it for analysis or reuse */
	copy_full_state(ctxt->old_state, state);

	/* Make sure this context is still the owner. */
	if (!cons_state_full_match(state, ctxt->state))
		return false;

	/*
	 * Having a safe point for take over and eventually a few
	 * duplicated characters or a full line is way better than a
	 * hostile takeover. Post processing can take care of the garbage.
	 * Continue if the requested priority is not sufficient.
	 */
	if (state.req_prio <= state.cur_prio)
		return true;

	/*
	 * A console printer within an unsafe region is allowed to continue.
	 * It can perform the handover when exiting the safe region. Otherwise
	 * a hostile takeover will be necessary.
	 */
	if (state.unsafe)
		return true;

	/* Release and hand over */
	cons_release(ctxt);
	/*
	 * This does not check whether the handover succeeded. The
	 * outermost callsite has to make the final decision whether printing
	 * should continue or not (via reacquire, possibly hostile). The
	 * console is unlocked already so go back all the way instead of
	 * trying to implement heuristics in tons of places.
	 */
	return false;
}
EXPORT_SYMBOL_GPL(console_can_proceed);

/**
 * __console_update_unsafe - Update the unsafe bit in @con->atomic_state
 * @wctxt:	The write context that was handed to the write function
 *
 * Returns:	True if the state is correct. False if a handover
 *		has been requested or if the console was taken
 *		over.
 *
 * Must be invoked before an unsafe driver section is entered.
 *
 * When this function returns false then the calling context is not allowed
 * to go forward and has to back out immediately and carefully. The buffer
 * content is no longer trusted either and the console lock is no longer
 * held.
 *
 * Internal helper to avoid duplicated code
 */
static bool __console_update_unsafe(struct cons_write_context *wctxt, bool unsafe)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);
	struct console *con = ctxt->console;
	struct cons_state new;

	do  {
		if (!console_can_proceed(wctxt))
			return false;
		/*
		 * console_can_proceed() saved the real state in
		 * ctxt->old_state
		 */
		copy_full_state(new, ctxt->old_state);
		new.unsafe = unsafe;

	} while (!cons_state_try_cmpxchg(con, CON_STATE_CUR, &ctxt->old_state, &new));

	copy_full_state(ctxt->state, new);
	return true;
}

/**
 * console_enter_unsafe - Enter an unsafe region in the driver
 * @wctxt:	The write context that was handed to the write function
 *
 * Returns:	True if the state is correct. False if a handover
 *		has been requested or if the console was taken
 *		over.
 *
 * Must be invoked before an unsafe driver section is entered.
 *
 * When this function returns false then the calling context is not allowed
 * to go forward and has to back out immediately and carefully. The buffer
 * content is no longer trusted either and the console lock is no longer
 * held.
 */
bool console_enter_unsafe(struct cons_write_context *wctxt)
{
	return __console_update_unsafe(wctxt, true);
}
EXPORT_SYMBOL_GPL(console_enter_unsafe);

/**
 * console_exit_unsafe - Exit an unsafe region in the driver
 * @wctxt:	The write context that was handed to the write function
 *
 * Returns:	True if the state is correct. False if a handover
 *		has been requested or if the console was taken
 *		over.
 *
 * Must be invoked before an unsafe driver section is exited.
 *
 * When this function returns false then the calling context is not allowed
 * to go forward and has to back out immediately and carefully. The buffer
 * content is no longer trusted either and the console lock is no longer
 * held.
 */
bool console_exit_unsafe(struct cons_write_context *wctxt)
{
	return __console_update_unsafe(wctxt, false);
}
EXPORT_SYMBOL_GPL(console_exit_unsafe);

/**
 * cons_get_record - Fill the buffer with the next pending ringbuffer record
 * @wctxt:	The write context which will be handed to the write function
 *
 * Returns:	True if there are records available. If the next record should
 *		be printed, the output buffer is filled and @wctxt->outbuf
 *		points to the text to print. If @wctxt->outbuf is NULL after
 *		the call, the record should not be printed but the caller must
 *		still update the console sequence number.
 *
 *		False means that there are no pending records anymore and the
 *		printing can stop.
 */
static bool cons_get_record(struct cons_write_context *wctxt)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);
	struct console *con = ctxt->console;
	bool is_extended = console_srcu_read_flags(con) & CON_EXTENDED;
	struct printk_message pmsg = {
		.pbufs = ctxt->pbufs,
	};

	if (!printk_get_next_message(&pmsg, ctxt->newseq, is_extended, true))
		return false;

	ctxt->newseq = pmsg.seq;
	ctxt->dropped += pmsg.dropped;

	if (pmsg.outbuf_len == 0) {
		wctxt->outbuf = NULL;
	} else {
		if (ctxt->dropped && !is_extended)
			console_prepend_dropped(&pmsg, ctxt->dropped);
		wctxt->outbuf = &pmsg.pbufs->outbuf[0];
	}

	wctxt->len = pmsg.outbuf_len;

	return true;
}

/**
 * cons_emit_record - Emit record in the acquired context
 * @wctxt:	The write context that will be handed to the write function
 *
 * Returns:	False if the operation was aborted (takeover or handover).
 *		True otherwise
 *
 * When false is returned, the caller is not allowed to touch console state.
 * The console is owned by someone else. If the caller wants to print more
 * it has to reacquire the console first.
 *
 * When true is returned, @wctxt->ctxt.backlog indicates whether there are
 * still records pending in the ringbuffer,
 */
static bool cons_emit_record(struct cons_write_context *wctxt)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);
	struct console *con = ctxt->console;
	bool done = false;

	/*
	 * @con->dropped is not protected in case of hostile takeovers so
	 * the update below is racy. Annotate it accordingly.
	 */
	ctxt->dropped = data_race(READ_ONCE(con->dropped));

	/* Fill the output buffer with the next record */
	ctxt->backlog = cons_get_record(wctxt);
	if (!ctxt->backlog)
		return true;

	/* Safety point. Don't touch state in case of takeover */
	if (!console_can_proceed(wctxt))
		return false;

	/* Counterpart to the read above */
	WRITE_ONCE(con->dropped, ctxt->dropped);

	/*
	 * In case of skipped records, Update sequence state in @con.
	 */
	if (!wctxt->outbuf)
		goto update;

	/* Tell the driver about potential unsafe state */
	wctxt->unsafe = ctxt->state.unsafe;

	if (!ctxt->thread && con->write_atomic) {
		done = con->write_atomic(con, wctxt);
	} else if (ctxt->thread && con->write_thread) {
		done = con->write_thread(con, wctxt);
	} else {
		cons_release(ctxt);
		WARN_ON_ONCE(1);
		return false;
	}

	/* If not done, the write was aborted due to takeover */
	if (!done)
		return false;

	/* If there was a dropped message, it has now been output. */
	if (ctxt->dropped) {
		ctxt->dropped = 0;
		/* Counterpart to the read above */
		WRITE_ONCE(con->dropped, ctxt->dropped);
	}
update:
	ctxt->newseq++;
	/*
	 * The sequence update attempt is not part of console_release()
	 * because in panic situations the console is not released by
	 * the panic CPU until all records are written. On 32bit the
	 * sequence is separate from state anyway.
	 */
	return cons_seq_try_update(ctxt);
}

/**
 * cons_kthread_should_wakeup - Check whether the printk thread should wakeup
 * @con:	Console to operate on
 * @ctxt:	The acquire context that contains the state
 *		at console_acquire()
 *
 * Returns: True if the thread should shutdown or if the console is allowed to
 * print and a record is available. False otherwise
 *
 * After the thread wakes up, it must first check if it should shutdown before
 * attempting any printing.
 */
static bool cons_kthread_should_wakeup(struct console *con, struct cons_context *ctxt)
{
	bool is_usable;
	short flags;
	int cookie;

	if (kthread_should_stop())
		return true;

	cookie = console_srcu_read_lock();
	flags = console_srcu_read_flags(con);
	is_usable = console_is_usable(con, flags);
	console_srcu_read_unlock(cookie);

	if (!is_usable)
		return false;

	/* This reads state and sequence on 64bit. On 32bit only state */
	cons_state_read(con, CON_STATE_CUR, &ctxt->state);

	/*
	 * Atomic printing is running on some other CPU. The owner
	 * will wake the console thread on unlock if necessary.
	 */
	if (ctxt->state.locked)
		return false;

	/* Bring the sequence in @ctxt up to date */
	cons_context_set_seq(ctxt);

	return prb_read_valid(prb, ctxt->oldseq, NULL);
}

/**
 * cons_kthread_func - The printk thread function
 * @__console:	Console to operate on
 */
static int cons_kthread_func(void *__console)
{
	struct console *con = __console;
	struct cons_write_context wctxt = {
		.ctxt.console	= con,
		.ctxt.prio	= CONS_PRIO_NORMAL,
		.ctxt.thread	= 1,
	};
	struct cons_context *ctxt = &ACCESS_PRIVATE(&wctxt, ctxt);
	unsigned long flags;
	short con_flags;
	bool backlog;
	int cookie;
	int ret;

	for (;;) {
		atomic_inc(&con->kthread_waiting);

		/*
		 * Provides a full memory barrier vs. cons_kthread_wake().
		 */
		ret = rcuwait_wait_event(&con->rcuwait,
					 cons_kthread_should_wakeup(con, ctxt),
					 TASK_INTERRUPTIBLE);

		atomic_dec(&con->kthread_waiting);

		if (kthread_should_stop())
			break;

		/* Wait was interrupted by a spurious signal, go back to sleep */
		if (ret)
			continue;

		for (;;) {
			cookie = console_srcu_read_lock();

			/*
			 * Ensure this stays on the CPU to make handover and
			 * takeover possible.
			 */
			if (con->port_lock)
				con->port_lock(con, true, &flags);
			else
				migrate_disable();

			/*
			 * Try to acquire the console without attempting to
			 * take over. If an atomic printer wants to hand
			 * back to the thread it simply wakes it up.
			 */
			if (!cons_try_acquire(ctxt))
				break;

			con_flags = console_srcu_read_flags(con);

			if (console_is_usable(con, con_flags)) {
				/*
				 * If the emit fails, this context is no
				 * longer the owner. Abort the processing and
				 * wait for new records to print.
				 */
				if (!cons_emit_record(&wctxt))
					break;
				backlog = ctxt->backlog;
			} else {
				backlog = false;
			}

			/*
			 * If the release fails, this context was not the
			 * owner. Abort the processing and wait for new
			 * records to print.
			 */
			if (!cons_release(ctxt))
				break;

			/* Backlog done? */
			if (!backlog)
				break;

			if (con->port_lock)
				con->port_lock(con, false, &flags);
			else
				migrate_enable();

			console_srcu_read_unlock(cookie);

			cond_resched();
		}
		if (con->port_lock)
			con->port_lock(con, false, &flags);
		else
			migrate_enable();

		console_srcu_read_unlock(cookie);
	}
	return 0;
}

/**
 * cons_irq_work - irq work to wake printk thread
 * @irq_work:	The irq work to operate on
 */
static void cons_irq_work(struct irq_work *irq_work)
{
	struct console *con = container_of(irq_work, struct console, irq_work);

	cons_kthread_wake(con);
}

/**
 * cons_wake_threads - Wake up printing threads
 *
 * A printing thread is only woken if it is within the @kthread_waiting
 * block. If it is not within the block (or enters the block later), it
 * will see any new records and continue printing on its own.
 */
void cons_wake_threads(void)
{
	struct console *con;
	int cookie;

	cookie = console_srcu_read_lock();
	for_each_console_srcu(con) {
		if (con->kthread && atomic_read(&con->kthread_waiting))
			irq_work_queue(&con->irq_work);
	}
	console_srcu_read_unlock(cookie);
}

/**
 * struct cons_cpu_state - Per CPU printk context state
 * @prio:	The current context priority level
 * @nesting:	Per priority nest counter
 */
struct cons_cpu_state {
	enum cons_prio	prio;
	int		nesting[CONS_PRIO_MAX];
};

static DEFINE_PER_CPU(struct cons_cpu_state, cons_pcpu_state);
static struct cons_cpu_state early_cons_pcpu_state __initdata;

/**
 * cons_get_cpu_state - Get the per CPU console state pointer
 *
 * Returns either a pointer to the per CPU state of the current CPU or to
 * the init data state during early boot.
 */
static __ref struct cons_cpu_state *cons_get_cpu_state(void)
{
	if (!printk_percpu_data_ready())
		return &early_cons_pcpu_state;

	return this_cpu_ptr(&cons_pcpu_state);
}

/**
 * cons_get_wctxt - Get the write context for atomic printing
 * @con:	Console to operate on
 * @prio:	Priority of the context
 *
 * Returns either the per CPU context or the builtin context for
 * early boot.
 */
static __ref struct cons_write_context *cons_get_wctxt(struct console *con,
						       enum cons_prio prio)
{
	if (!con->pcpu_data)
		return &early_cons_ctxt_data.wctxt[prio];

	return &this_cpu_ptr(con->pcpu_data)->wctxt[prio];
}

/**
 * cons_atomic_try_acquire - Try to acquire the console for atomic printing
 * @con:	The console to acquire
 * @ctxt:	The console context instance to work on
 * @prio:	The priority of the current context
 */
static bool cons_atomic_try_acquire(struct console *con, struct cons_context *ctxt,
				    enum cons_prio prio, bool skip_unsafe)
{
	memset(ctxt, 0, sizeof(*ctxt));
	ctxt->console		= con;
	ctxt->spinwait_max_us	= 2000;
	ctxt->prio		= prio;
	ctxt->spinwait		= 1;

	/* Try to acquire it directly or via a friendly handover */
	if (cons_try_acquire(ctxt))
		return true;

	/* Investigate whether a hostile takeover is due */
	if (ctxt->old_state.cur_prio >= prio)
		return false;

	if (!ctxt->old_state.unsafe || !skip_unsafe)
		ctxt->hostile = 1;
	return cons_try_acquire(ctxt);
}

/**
 * cons_atomic_flush_con - Flush one console in atomic mode
 * @wctxt:		The write context struct to use for this context
 * @con:		The console to flush
 * @prio:		The priority of the current context
 * @skip_unsafe:	True, to avoid unsafe hostile takeovers
 */
static void cons_atomic_flush_con(struct cons_write_context *wctxt, struct console *con,
				  enum cons_prio prio, bool skip_unsafe)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);
	bool wake_thread = false;
	short flags;

	if (!cons_atomic_try_acquire(con, ctxt, prio, skip_unsafe))
		return;

	do {
		flags = console_srcu_read_flags(con);

		if (!console_is_usable(con, flags))
			break;

		/*
		 * For normal prio messages let the printer thread handle
		 * the printing if it is available.
		 */
		if (prio <= CONS_PRIO_NORMAL && con->kthread) {
			wake_thread = true;
			break;
		}

		/*
		 * cons_emit_record() returns false when the console was
		 * handed over or taken over. In both cases the context is
		 * no longer valid.
		 */
		if (!cons_emit_record(wctxt))
			return;
	} while (ctxt->backlog);

	cons_release(ctxt);

	if (wake_thread && atomic_read(&con->kthread_waiting))
		irq_work_queue(&con->irq_work);
}

/**
 * cons_atomic_flush - Flush consoles in atomic mode if required
 * @printk_caller_wctxt:	The write context struct to use for this
 *				context (for printk() context only)
 * @skip_unsafe:		True, to avoid unsafe hostile takeovers
 */
void cons_atomic_flush(struct cons_write_context *printk_caller_wctxt, bool skip_unsafe)
{
	struct cons_write_context *wctxt;
	struct cons_cpu_state *cpu_state;
	struct console *con;
	short flags;
	int cookie;

	cpu_state = cons_get_cpu_state();

	/*
	 * When in an elevated priority, the printk() calls are not
	 * individually flushed. This is to allow the full output to
	 * be dumped to the ringbuffer before starting with printing
	 * the backlog.
	 */
	if (cpu_state->prio > CONS_PRIO_NORMAL && printk_caller_wctxt)
		return;

	/*
	 * Let the outermost write of this priority print. This avoids
	 * nasty hackery for nested WARN() where the printing itself
	 * generates one.
	 *
	 * cpu_state->prio <= CONS_PRIO_NORMAL is not subject to nesting
	 * and can proceed in order to allow atomic printing when consoles
	 * do not have a printer thread.
	 */
	if (cpu_state->prio > CONS_PRIO_NORMAL &&
	    cpu_state->nesting[cpu_state->prio] != 1)
		return;

	cookie = console_srcu_read_lock();
	for_each_console_srcu(con) {
		if (!con->write_atomic)
			continue;

		flags = console_srcu_read_flags(con);

		if (!console_is_usable(con, flags))
			continue;

		if (cpu_state->prio > CONS_PRIO_NORMAL || !con->kthread) {
			if (printk_caller_wctxt)
				wctxt = printk_caller_wctxt;
			else
				wctxt = cons_get_wctxt(con, cpu_state->prio);
			cons_atomic_flush_con(wctxt, con, cpu_state->prio, skip_unsafe);
		}
	}
	console_srcu_read_unlock(cookie);
}

/**
 * cons_atomic_enter - Enter a context that enforces atomic printing
 * @prio:	Priority of the context
 *
 * Returns:	The previous priority that needs to be fed into
 *		the corresponding cons_atomic_exit()
 */
enum cons_prio cons_atomic_enter(enum cons_prio prio)
{
	struct cons_cpu_state *cpu_state;
	enum cons_prio prev_prio;

	migrate_disable();
	cpu_state = cons_get_cpu_state();

	prev_prio = cpu_state->prio;
	if (prev_prio < prio)
		cpu_state->prio = prio;

	/*
	 * Increment the nesting on @cpu_state->prio so a WARN()
	 * nested into a panic printout does not attempt to
	 * scribble state.
	 */
	cpu_state->nesting[cpu_state->prio]++;

	return prev_prio;
}

/**
 * cons_atomic_exit - Exit a context that enforces atomic printing
 * @prio:	Priority of the context to leave
 * @prev_prio:	Priority of the previous context for restore
 *
 * @prev_prio is the priority returned by the corresponding cons_atomic_enter().
 */
void cons_atomic_exit(enum cons_prio prio, enum cons_prio prev_prio)
{
	struct cons_cpu_state *cpu_state;

	cons_atomic_flush(NULL, true);

	cpu_state = cons_get_cpu_state();

	if (cpu_state->prio == CONS_PRIO_PANIC)
		cons_atomic_flush(NULL, false);

	/*
	 * Undo the nesting of cons_atomic_enter() at the CPU state
	 * priority.
	 */
	cpu_state->nesting[cpu_state->prio]--;

	/*
	 * Restore the previous priority, which was returned by
	 * cons_atomic_enter().
	 */
	cpu_state->prio = prev_prio;

	migrate_enable();
}

/**
 * cons_kthread_stop - Stop a printk thread
 * @con:	Console to operate on
 */
static void cons_kthread_stop(struct console *con)
{
	lockdep_assert_console_list_lock_held();

	if (!con->kthread)
		return;

	kthread_stop(con->kthread);
	con->kthread = NULL;

	kfree(con->thread_pbufs);
	con->thread_pbufs = NULL;
}

/**
 * cons_kthread_create - Create a printk thread
 * @con:	Console to operate on
 *
 * If it fails, let the console proceed. The atomic part might
 * be usable and useful.
 */
void cons_kthread_create(struct console *con)
{
	struct task_struct *kt;
	struct console *c;

	lockdep_assert_console_list_lock_held();

	if (!(con->flags & CON_NO_BKL) || !con->write_thread)
		return;

	if (!printk_threads_enabled || con->kthread)
		return;

	/*
	 * Printer threads cannot be started as long as any boot console is
	 * registered because there is no way to synchronize the hardware
	 * registers between boot console code and regular console code.
	 */
	for_each_console(c) {
		if (c->flags & CON_BOOT)
			return;
	}
	have_boot_console = false;

	con->thread_pbufs = kmalloc(sizeof(*con->thread_pbufs), GFP_KERNEL);
	if (!con->thread_pbufs) {
		con_printk(KERN_ERR, con, "failed to allocate printing thread buffers\n");
		return;
	}

	kt = kthread_run(cons_kthread_func, con, "pr/%s%d", con->name, con->index);
	if (IS_ERR(kt)) {
		con_printk(KERN_ERR, con, "failed to start printing thread\n");
		kfree(con->thread_pbufs);
		con->thread_pbufs = NULL;
		return;
	}

	con->kthread = kt;

	/*
	 * It is important that console printing threads are scheduled
	 * shortly after a printk call and with generous runtime budgets.
	 */
	sched_set_normal(con->kthread, -20);
}

static int __init printk_setup_threads(void)
{
	struct console *con;

	if (printk_force_atomic)
		return 0;

	console_list_lock();
	printk_threads_enabled = true;
	for_each_console(con)
		cons_kthread_create(con);
	if (have_bkl_console)
		console_bkl_kthread_create();
	console_list_unlock();
	return 0;
}
early_initcall(printk_setup_threads);

/**
 * cons_nobkl_init - Initialize the NOBKL console specific data
 * @con:	Console to initialize
 *
 * Returns: True on success. False otherwise and the console cannot be used.
 */
bool cons_nobkl_init(struct console *con)
{
	struct cons_state state = { };

	if (!cons_alloc_percpu_data(con))
		return false;

	rcuwait_init(&con->rcuwait);
	atomic_set(&con->kthread_waiting, 0);
	init_irq_work(&con->irq_work, cons_irq_work);
	cons_state_set(con, CON_STATE_CUR, &state);
	cons_state_set(con, CON_STATE_REQ, &state);
	cons_seq_init(con);
	cons_kthread_create(con);
	return true;
}

/**
 * cons_nobkl_cleanup - Cleanup the NOBKL console specific data
 * @con:	Console to cleanup
 */
void cons_nobkl_cleanup(struct console *con)
{
	struct cons_state state = { };

	cons_kthread_stop(con);
	cons_state_set(con, CON_STATE_CUR, &state);
	cons_state_set(con, CON_STATE_REQ, &state);
	cons_free_percpu_data(con);
}

/**
 * printk_kthread_shutdown - shutdown all threaded printers
 *
 * On system shutdown all threaded printers are stopped. This allows printk
 * to transition back to atomic printing, thus providing a robust mechanism
 * for the final shutdown/reboot messages to be output.
 */
static void printk_kthread_shutdown(void)
{
	struct console *con;

	console_list_lock();
	for_each_console(con) {
		if (con->flags & CON_NO_BKL)
			cons_kthread_stop(con);
	}
	console_list_unlock();
}

static struct syscore_ops printk_syscore_ops = {
	.shutdown = printk_kthread_shutdown,
};

static int __init printk_init_ops(void)
{
	register_syscore_ops(&printk_syscore_ops);
	return 0;
}
device_initcall(printk_init_ops);
