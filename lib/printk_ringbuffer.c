// SPDX-License-Identifier: GPL-2.0
#include <linux/smp.h>
#include <linux/printk_ringbuffer.h>

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
