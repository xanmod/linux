/*
 * Copyright (C) 2005-2017 Junjiro R. Okajima
 *
 * This program, aufs is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * simple read-write semaphore wrappers
 */

#ifndef __AUFS_RWSEM_H__
#define __AUFS_RWSEM_H__

#ifdef __KERNEL__

#include "debug.h"

struct au_rwsem {
	struct rw_semaphore	rwsem;
#ifdef CONFIG_AUFS_DEBUG
	/* just for debugging, not almighty counter */
	atomic_t		rcnt, wcnt;
#endif
};

#ifdef CONFIG_LOCKDEP
#define au_lockdep_set_name(rw)						\
	lockdep_set_class_and_name(&(rw)->rwsem,			\
				   /*original key*/(rw)->rwsem.dep_map.key, \
				   /*name*/#rw)
#else
#define au_lockdep_set_name(rw) do {} while (0)
#endif

#ifdef CONFIG_AUFS_DEBUG
#define AuDbgCntInit(rw) do { \
	atomic_set(&(rw)->rcnt, 0); \
	atomic_set(&(rw)->wcnt, 0); \
	smp_mb(); /* atomic set */ \
} while (0)

#define AuDbgCnt(rw, cnt)	atomic_read(&(rw)->cnt)
#define AuDbgCntInc(rw, cnt)	atomic_inc(&(rw)->cnt)
#define AuDbgCntDec(rw, cnt)	WARN_ON(atomic_dec_return(&(rw)->cnt) < 0)
#define AuDbgRcntInc(rw)	AuDbgCntInc(rw, rcnt)
#define AuDbgRcntDec(rw)	AuDbgCntDec(rw, rcnt)
#define AuDbgWcntInc(rw)	AuDbgCntInc(rw, wcnt)
#define AuDbgWcntDec(rw)	AuDbgCntDec(rw, wcnt)
#else
#define AuDbgCnt(rw, cnt)	0
#define AuDbgCntInit(rw)	do {} while (0)
#define AuDbgRcntInc(rw)	do {} while (0)
#define AuDbgRcntDec(rw)	do {} while (0)
#define AuDbgWcntInc(rw)	do {} while (0)
#define AuDbgWcntDec(rw)	do {} while (0)
#endif /* CONFIG_AUFS_DEBUG */

/* to debug easier, do not make them inlined functions */
#define AuRwMustNoWaiters(rw)	AuDebugOn(rwsem_is_contended(&(rw)->rwsem))
/* rwsem_is_locked() is unusable */
#define AuRwMustReadLock(rw)	AuDebugOn(AuDbgCnt(rw, rcnt) <= 0)
#define AuRwMustWriteLock(rw)	AuDebugOn(AuDbgCnt(rw, wcnt) <= 0)
#define AuRwMustAnyLock(rw)	AuDebugOn(AuDbgCnt(rw, rcnt) <= 0	\
					  && AuDbgCnt(rw, wcnt) <= 0)
#define AuRwDestroy(rw)		AuDebugOn(AuDbgCnt(rw, rcnt)		\
					  || AuDbgCnt(rw, wcnt))

#define au_rw_init(rw) do {			\
		AuDbgCntInit(rw);		\
		init_rwsem(&(rw)->rwsem);	\
		au_lockdep_set_name(rw);	\
	} while (0)

#define au_rw_init_wlock(rw) do {		\
		au_rw_init(rw);			\
		down_write(&(rw)->rwsem);	\
		AuDbgWcntInc(rw);		\
	} while (0)

#define au_rw_init_wlock_nested(rw, lsc) do { \
		au_rw_init(rw);				\
		down_write_nested(&(rw)->rwsem, lsc);	\
		AuDbgWcntInc(rw);			\
	} while (0)

static inline void au_rw_read_lock(struct au_rwsem *rw)
{
	down_read(&rw->rwsem);
	AuDbgRcntInc(rw);
}

static inline void au_rw_read_lock_nested(struct au_rwsem *rw, unsigned int lsc)
{
	down_read_nested(&rw->rwsem, lsc);
	AuDbgRcntInc(rw);
}

static inline void au_rw_read_unlock(struct au_rwsem *rw)
{
	AuRwMustReadLock(rw);
	AuDbgRcntDec(rw);
	up_read(&rw->rwsem);
}

static inline void au_rw_dgrade_lock(struct au_rwsem *rw)
{
	AuRwMustWriteLock(rw);
	AuDbgRcntInc(rw);
	AuDbgWcntDec(rw);
	downgrade_write(&rw->rwsem);
}

static inline void au_rw_write_lock(struct au_rwsem *rw)
{
	down_write(&rw->rwsem);
	AuDbgWcntInc(rw);
}

static inline void au_rw_write_lock_nested(struct au_rwsem *rw,
					   unsigned int lsc)
{
	down_write_nested(&rw->rwsem, lsc);
	AuDbgWcntInc(rw);
}

static inline void au_rw_write_unlock(struct au_rwsem *rw)
{
	AuRwMustWriteLock(rw);
	AuDbgWcntDec(rw);
	up_write(&rw->rwsem);
}

/* why is not _nested version defined */
static inline int au_rw_read_trylock(struct au_rwsem *rw)
{
	int ret;

	ret = down_read_trylock(&rw->rwsem);
	if (ret)
		AuDbgRcntInc(rw);
	return ret;
}

static inline int au_rw_write_trylock(struct au_rwsem *rw)
{
	int ret;

	ret = down_write_trylock(&rw->rwsem);
	if (ret)
		AuDbgWcntInc(rw);
	return ret;
}

#undef AuDbgCntDec
#undef AuDbgRcntInc
#undef AuDbgRcntDec
#undef AuDbgWcntDec

#define AuSimpleLockRwsemFuncs(prefix, param, rwsem) \
static inline void prefix##_read_lock(param) \
{ au_rw_read_lock(rwsem); } \
static inline void prefix##_write_lock(param) \
{ au_rw_write_lock(rwsem); } \
static inline int prefix##_read_trylock(param) \
{ return au_rw_read_trylock(rwsem); } \
static inline int prefix##_write_trylock(param) \
{ return au_rw_write_trylock(rwsem); }
/* why is not _nested version defined */
/* static inline void prefix##_read_trylock_nested(param, lsc)
{ au_rw_read_trylock_nested(rwsem, lsc)); }
static inline void prefix##_write_trylock_nestd(param, lsc)
{ au_rw_write_trylock_nested(rwsem, lsc); } */

#define AuSimpleUnlockRwsemFuncs(prefix, param, rwsem) \
static inline void prefix##_read_unlock(param) \
{ au_rw_read_unlock(rwsem); } \
static inline void prefix##_write_unlock(param) \
{ au_rw_write_unlock(rwsem); } \
static inline void prefix##_downgrade_lock(param) \
{ au_rw_dgrade_lock(rwsem); }

#define AuSimpleRwsemFuncs(prefix, param, rwsem) \
	AuSimpleLockRwsemFuncs(prefix, param, rwsem) \
	AuSimpleUnlockRwsemFuncs(prefix, param, rwsem)

#endif /* __KERNEL__ */
#endif /* __AUFS_RWSEM_H__ */
