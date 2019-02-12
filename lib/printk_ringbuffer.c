// SPDX-License-Identifier: GPL-2.0
#include <linux/smp.h>
#include <linux/printk_ringbuffer.h>

#define PRB_SIZE(rb) (1 << rb->size_bits)
#define PRB_SIZE_BITMASK(rb) (PRB_SIZE(rb) - 1)
#define PRB_INDEX(rb, lpos) (lpos & PRB_SIZE_BITMASK(rb))
#define PRB_WRAPS(rb, lpos) (lpos >> rb->size_bits)
#define PRB_WRAP_LPOS(rb, lpos, xtra) \
	((PRB_WRAPS(rb, lpos) + xtra) << rb->size_bits)
#define PRB_DATA_ALIGN sizeof(long)

static bool __prb_trylock(struct prb_cpulock *cpu_lock,
			  unsigned int *cpu_store)
{
	unsigned long *flags;
	unsigned int cpu;

	cpu = get_cpu();

	*cpu_store = atomic_read(&cpu_lock->owner);
	/* memory barrier to ensure the current lock owner is visible */
	smp_rmb();
	if (*cpu_store == -1) {
		flags = per_cpu_ptr(cpu_lock->irqflags, cpu);
		local_irq_save(*flags);
		if (atomic_try_cmpxchg_acquire(&cpu_lock->owner,
					       cpu_store, cpu)) {
			return true;
		}
		local_irq_restore(*flags);
	} else if (*cpu_store == cpu) {
		return true;
	}

	put_cpu();
	return false;
}

/*
 * prb_lock: Perform a processor-reentrant spin lock.
 * @cpu_lock: A pointer to the lock object.
 * @cpu_store: A "flags" pointer to store lock status information.
 *
 * If no processor has the lock, the calling processor takes the lock and
 * becomes the owner. If the calling processor is already the owner of the
 * lock, this function succeeds immediately. If lock is locked by another
 * processor, this function spins until the calling processor becomes the
 * owner.
 *
 * It is safe to call this function from any context and state.
 */
void prb_lock(struct prb_cpulock *cpu_lock, unsigned int *cpu_store)
{
	for (;;) {
		if (__prb_trylock(cpu_lock, cpu_store))
			break;
		cpu_relax();
	}
}

/*
 * prb_unlock: Perform a processor-reentrant spin unlock.
 * @cpu_lock: A pointer to the lock object.
 * @cpu_store: A "flags" object storing lock status information.
 *
 * Release the lock. The calling processor must be the owner of the lock.
 *
 * It is safe to call this function from any context and state.
 */
void prb_unlock(struct prb_cpulock *cpu_lock, unsigned int cpu_store)
{
	unsigned long *flags;
	unsigned int cpu;

	cpu = atomic_read(&cpu_lock->owner);
	atomic_set_release(&cpu_lock->owner, cpu_store);

	if (cpu_store == -1) {
		flags = per_cpu_ptr(cpu_lock->irqflags, cpu);
		local_irq_restore(*flags);
	}

	put_cpu();
}

static struct prb_entry *to_entry(struct printk_ringbuffer *rb,
				  unsigned long lpos)
{
	char *buffer = rb->buffer;
	buffer += PRB_INDEX(rb, lpos);
	return (struct prb_entry *)buffer;
}

static int calc_next(struct printk_ringbuffer *rb, unsigned long tail,
		     unsigned long lpos, int size, unsigned long *calced_next)
{
	unsigned long next_lpos;
	int ret = 0;
again:
	next_lpos = lpos + size;
	if (next_lpos - tail > PRB_SIZE(rb))
		return -1;

	if (PRB_WRAPS(rb, lpos) != PRB_WRAPS(rb, next_lpos)) {
		lpos = PRB_WRAP_LPOS(rb, next_lpos, 0);
		ret |= 1;
		goto again;
	}

	*calced_next = next_lpos;
	return ret;
}

static bool push_tail(struct printk_ringbuffer *rb, unsigned long tail)
{
	unsigned long new_tail;
	struct prb_entry *e;
	unsigned long head;

	if (tail != atomic_long_read(&rb->tail))
		return true;

	e = to_entry(rb, tail);
	if (e->size != -1)
		new_tail = tail + e->size;
	else
		new_tail = PRB_WRAP_LPOS(rb, tail, 1);

	/* make sure the new tail does not overtake the head */
	head = atomic_long_read(&rb->head);
	if (head - new_tail > PRB_SIZE(rb))
		return false;

	atomic_long_cmpxchg(&rb->tail, tail, new_tail);
	return true;
}

/*
 * prb_commit: Commit a reserved entry to the ring buffer.
 * @h: An entry handle referencing the data entry to commit.
 *
 * Commit data that has been reserved using prb_reserve(). Once the data
 * block has been committed, it can be invalidated at any time. If a writer
 * is interested in using the data after committing, the writer should make
 * its own copy first or use the prb_iter_ reader functions to access the
 * data in the ring buffer.
 *
 * It is safe to call this function from any context and state.
 */
void prb_commit(struct prb_handle *h)
{
	struct printk_ringbuffer *rb = h->rb;
	struct prb_entry *e;
	unsigned long head;
	unsigned long res;

	for (;;) {
		if (atomic_read(&rb->ctx) != 1) {
			/* the interrupted context will fixup head */
			atomic_dec(&rb->ctx);
			break;
		}
		/* assign sequence numbers before moving head */
		head = atomic_long_read(&rb->head);
		res = atomic_long_read(&rb->reserve);
		while (head != res) {
			e = to_entry(rb, head);
			if (e->size == -1) {
				head = PRB_WRAP_LPOS(rb, head, 1);
				continue;
			}
			e->seq = ++rb->seq;
			head += e->size;
		}
		atomic_long_set_release(&rb->head, res);
		atomic_dec(&rb->ctx);

		if (atomic_long_read(&rb->reserve) == res)
			break;
		atomic_inc(&rb->ctx);
	}

	prb_unlock(rb->cpulock, h->cpu);
}

/*
 * prb_reserve: Reserve an entry within a ring buffer.
 * @h: An entry handle to be setup and reference an entry.
 * @rb: A ring buffer to reserve data within.
 * @size: The number of bytes to reserve.
 *
 * Reserve an entry of at least @size bytes to be used by the caller. If
 * successful, the data region of the entry belongs to the caller and cannot
 * be invalidated by any other task/context. For this reason, the caller
 * should call prb_commit() as quickly as possible in order to avoid preventing
 * other tasks/contexts from reserving data in the case that the ring buffer
 * has wrapped.
 *
 * It is safe to call this function from any context and state.
 *
 * Returns a pointer to the reserved entry (and @h is setup to reference that
 * entry) or NULL if it was not possible to reserve data.
 */
char *prb_reserve(struct prb_handle *h, struct printk_ringbuffer *rb,
		  unsigned int size)
{
	unsigned long tail, res1, res2;
	int ret;

	if (size == 0)
		return NULL;
	size += sizeof(struct prb_entry);
	size += PRB_DATA_ALIGN - 1;
	size &= ~(PRB_DATA_ALIGN - 1);
	if (size >= PRB_SIZE(rb))
		return NULL;

	h->rb = rb;
	prb_lock(rb->cpulock, &h->cpu);

	atomic_inc(&rb->ctx);

	do {
		for (;;) {
			tail = atomic_long_read(&rb->tail);
			res1 = atomic_long_read(&rb->reserve);
			ret = calc_next(rb, tail, res1, size, &res2);
			if (ret >= 0)
				break;
			if (!push_tail(rb, tail)) {
				prb_commit(h);
				return NULL;
			}
		}
	} while (!atomic_long_try_cmpxchg_acquire(&rb->reserve, &res1, res2));

	h->entry = to_entry(rb, res1);

	if (ret) {
		/* handle wrap */
		h->entry->size = -1;
		h->entry = to_entry(rb, PRB_WRAP_LPOS(rb, res2, 0));
	}

	h->entry->size = size;

	return &h->entry->data[0];
}
