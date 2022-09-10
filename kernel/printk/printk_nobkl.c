// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2022 Linutronix GmbH, John Ogness
// Copyright (C) 2022 Intel, Thomas Gleixner

#include <linux/kernel.h>
#include <linux/console.h>
#include <linux/delay.h>
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
static bool __maybe_unused cons_seq_try_update(struct cons_context *ctxt)
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
static bool __maybe_unused cons_seq_try_update(struct cons_context *ctxt)
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

	cons_state_set(con, CON_STATE_CUR, &state);
	cons_state_set(con, CON_STATE_REQ, &state);
	cons_seq_init(con);
	return true;
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
	cons_free_percpu_data(con);
}
