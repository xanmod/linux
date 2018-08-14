// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2018 Junjiro R. Okajima
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
 * external inode number translation table and bitmap
 *
 * things to consider
 * - the lifetime
 *   + au_xino object
 *   + XINO files (xino, xib, xigen)
 *   + dynamic debugfs entries (xiN)
 *   + static debugfs entries (xib, xigen)
 *   + static sysfs entry (xi_path)
 * - several entry points to handle them.
 *   + mount(2) without xino option (default)
 *   + mount(2) with xino option
 *   + mount(2) with noxino option
 *   + umount(2)
 *   + remount with add/del branches
 *   + remount with xino/noxino options
 */

#include <linux/seq_file.h>
#include <linux/statfs.h>
#include "aufs.h"

static aufs_bindex_t sbr_find_shared(struct super_block *sb, aufs_bindex_t btop,
				     aufs_bindex_t bbot,
				     struct super_block *h_sb)
{
	/* todo: try binary-search if the branches are many */
	for (; btop <= bbot; btop++)
		if (h_sb == au_sbr_sb(sb, btop))
			return btop;
	return -1;
}

/*
 * find another branch who is on the same filesystem of the specified
 * branch{@btgt}. search until @bbot.
 */
static aufs_bindex_t is_sb_shared(struct super_block *sb, aufs_bindex_t btgt,
				  aufs_bindex_t bbot)
{
	aufs_bindex_t bindex;
	struct super_block *tgt_sb;

	tgt_sb = au_sbr_sb(sb, btgt);
	bindex = sbr_find_shared(sb, /*btop*/0, btgt - 1, tgt_sb);
	if (bindex < 0)
		bindex = sbr_find_shared(sb, btgt + 1, bbot, tgt_sb);

	return bindex;
}

/* ---------------------------------------------------------------------- */

/*
 * stop unnecessary notify events at creating xino files
 */
struct au_xino_lock_dir {
	struct au_hinode *hdir;
	struct dentry *parent;
	struct inode *dir;
};

static struct dentry *au_dget_parent_lock(struct dentry *dentry,
					  unsigned int lsc)
{
	struct dentry *parent;
	struct inode *dir;

	parent = dget_parent(dentry);
	dir = d_inode(parent);
	inode_lock_nested(dir, lsc);
#if 0 /* it should not happen */
	spin_lock(&dentry->d_lock);
	if (unlikely(dentry->d_parent != parent)) {
		spin_unlock(&dentry->d_lock);
		inode_unlock(dir);
		dput(parent);
		parent = NULL;
		goto out;
	}
	spin_unlock(&dentry->d_lock);

out:
#endif
	return parent;
}

static void au_xino_lock_dir(struct super_block *sb, struct path *xipath,
			     struct au_xino_lock_dir *ldir)
{
	aufs_bindex_t brid, bindex;

	ldir->hdir = NULL;
	bindex = -1;
	brid = au_xino_brid(sb);
	if (brid >= 0)
		bindex = au_br_index(sb, brid);
	if (bindex >= 0) {
		/* rw branch root */
		ldir->hdir = au_hi(d_inode(sb->s_root), bindex);
		au_hn_inode_lock_nested(ldir->hdir, AuLsc_I_PARENT);
	} else {
		/* other */
		ldir->parent = au_dget_parent_lock(xipath->dentry,
						   AuLsc_I_PARENT);
		ldir->dir = d_inode(ldir->parent);
	}
}

static void au_xino_unlock_dir(struct au_xino_lock_dir *ldir)
{
	if (ldir->hdir)
		au_hn_inode_unlock(ldir->hdir);
	else {
		inode_unlock(ldir->dir);
		dput(ldir->parent);
	}
}

/* ---------------------------------------------------------------------- */

/*
 * create and set a new xino file
 */
struct file *au_xino_create(struct super_block *sb, char *fpath, int silent)
{
	struct file *file;
	struct dentry *h_parent, *d;
	struct inode *h_dir, *inode;
	int err;

	/*
	 * at mount-time, and the xino file is the default path,
	 * hnotify is disabled so we have no notify events to ignore.
	 * when a user specified the xino, we cannot get au_hdir to be ignored.
	 */
	file = vfsub_filp_open(fpath, O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE
			       /* | __FMODE_NONOTIFY */,
			       0666);
	if (IS_ERR(file)) {
		if (!silent)
			pr_err("open %s(%ld)\n", fpath, PTR_ERR(file));
		return file;
	}

	/* keep file count */
	err = 0;
	d = file->f_path.dentry;
	h_parent = au_dget_parent_lock(d, AuLsc_I_PARENT);
	/* mnt_want_write() is unnecessary here */
	h_dir = d_inode(h_parent);
	inode = file_inode(file);
	/* no delegation since it is just created */
	if (inode->i_nlink)
		err = vfsub_unlink(h_dir, &file->f_path, /*delegated*/NULL,
				   /*force*/0);
	inode_unlock(h_dir);
	dput(h_parent);
	if (unlikely(err)) {
		if (!silent)
			pr_err("unlink %s(%d)\n", fpath, err);
		goto out;
	}

	err = -EINVAL;
	if (unlikely(sb == d->d_sb)) {
		if (!silent)
			pr_err("%s must be outside\n", fpath);
		goto out;
	}
	if (unlikely(au_test_fs_bad_xino(d->d_sb))) {
		if (!silent)
			pr_err("xino doesn't support %s(%s)\n",
			       fpath, au_sbtype(d->d_sb));
		goto out;
	}
	return file; /* success */

out:
	fput(file);
	file = ERR_PTR(err);
	return file;
}

/*
 * create a new xinofile at the same place/path as @base.
 */
struct file *au_xino_create2(struct super_block *sb, struct path *base,
			     struct file *copy_src)
{
	struct file *file;
	struct dentry *dentry, *parent;
	struct inode *dir, *delegated;
	struct qstr *name;
	struct path path;
	int err, do_unlock;
	struct au_xino_lock_dir ldir;

	do_unlock = 1;
	au_xino_lock_dir(sb, base, &ldir);
	dentry = base->dentry;
	parent = dentry->d_parent; /* dir inode is locked */
	dir = d_inode(parent);
	IMustLock(dir);

	name = &dentry->d_name;
	path.dentry = vfsub_lookup_one_len(name->name, parent, name->len);
	if (IS_ERR(path.dentry)) {
		file = (void *)path.dentry;
		pr_err("%pd lookup err %ld\n", dentry, PTR_ERR(path.dentry));
		goto out;
	}

	/* no need to mnt_want_write() since we call dentry_open() later */
	err = vfs_create(dir, path.dentry, 0666, NULL);
	if (unlikely(err)) {
		file = ERR_PTR(err);
		pr_err("%pd create err %d\n", dentry, err);
		goto out_dput;
	}

	path.mnt = base->mnt;
	file = vfsub_dentry_open(&path,
				 O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE
				 /* | __FMODE_NONOTIFY */);
	if (IS_ERR(file)) {
		pr_err("%pd open err %ld\n", dentry, PTR_ERR(file));
		goto out_dput;
	}

	delegated = NULL;
	err = vfsub_unlink(dir, &file->f_path, &delegated, /*force*/0);
	au_xino_unlock_dir(&ldir);
	do_unlock = 0;
	if (unlikely(err == -EWOULDBLOCK)) {
		pr_warn("cannot retry for NFSv4 delegation"
			" for an internal unlink\n");
		iput(delegated);
	}
	if (unlikely(err)) {
		pr_err("%pd unlink err %d\n", dentry, err);
		goto out_fput;
	}

	if (copy_src) {
		/* no one can touch copy_src xino */
		err = au_copy_file(file, copy_src, vfsub_f_size_read(copy_src));
		if (unlikely(err)) {
			pr_err("%pd copy err %d\n", dentry, err);
			goto out_fput;
		}
	}
	goto out_dput; /* success */

out_fput:
	fput(file);
	file = ERR_PTR(err);
out_dput:
	dput(path.dentry);
out:
	if (do_unlock)
		au_xino_unlock_dir(&ldir);
	return file;
}

/* ---------------------------------------------------------------------- */

/*
 * truncate xino files
 */
int au_xino_trunc(struct super_block *sb, aufs_bindex_t bindex)
{
	int err;
	unsigned long jiffy;
	blkcnt_t blocks;
	aufs_bindex_t bbot;
	struct kstatfs *st;
	struct au_branch *br;
	struct file *new_xino, *file;
	struct path *path;

	err = -ENOMEM;
	st = kmalloc(sizeof(*st), GFP_NOFS);
	if (unlikely(!st))
		goto out;

	err = -EINVAL;
	bbot = au_sbbot(sb);
	if (unlikely(bindex < 0 || bbot < bindex))
		goto out_st;
	br = au_sbr(sb, bindex);
	file = au_xino_file(br);
	if (!file)
		goto out_st;

	path = &file->f_path;
	err = vfs_statfs(path, st);
	if (unlikely(err))
		AuErr1("statfs err %d, ignored\n", err);
	jiffy = jiffies;
	blocks = file_inode(file)->i_blocks;
	pr_info("begin truncating xino(b%d), ib%llu, %llu/%llu free blks\n",
		bindex, (u64)blocks, st->f_bfree, st->f_blocks);

	new_xino = au_xino_create2(sb, path, file);
	err = PTR_ERR(new_xino);
	if (IS_ERR(new_xino)) {
		pr_err("err %d, ignored\n", err);
		goto out_st;
	}
	err = 0;
	au_xino_file_set(br, new_xino);

	err = vfs_statfs(&new_xino->f_path, st);
	if (!err) {
		pr_info("end truncating xino(b%d), ib%llu, %llu/%llu free blks\n",
			bindex, (u64)file_inode(new_xino)->i_blocks,
			st->f_bfree, st->f_blocks);
		if (file_inode(new_xino)->i_blocks < blocks)
			au_sbi(sb)->si_xino_jiffy = jiffy;
	} else
		AuErr1("statfs err %d, ignored\n", err);
	fput(new_xino);

out_st:
	kfree(st);
out:
	return err;
}

struct xino_do_trunc_args {
	struct super_block *sb;
	struct au_branch *br;
};

static void xino_do_trunc(void *_args)
{
	struct xino_do_trunc_args *args = _args;
	struct super_block *sb;
	struct au_branch *br;
	struct inode *dir;
	int err;
	aufs_bindex_t bindex;

	err = 0;
	sb = args->sb;
	dir = d_inode(sb->s_root);
	br = args->br;

	si_noflush_write_lock(sb);
	ii_read_lock_parent(dir);
	bindex = au_br_index(sb, br->br_id);
	err = au_xino_trunc(sb, bindex);
	ii_read_unlock(dir);
	if (unlikely(err))
		pr_warn("err b%d, (%d)\n", bindex, err);
	atomic_dec(&br->br_xino->xi_truncating);
	au_br_put(br);
	si_write_unlock(sb);
	au_nwt_done(&au_sbi(sb)->si_nowait);
	kfree(args);
}

static int xino_trunc_test(struct super_block *sb, struct au_branch *br)
{
	int err;
	struct kstatfs st;
	struct au_sbinfo *sbinfo;
	struct file *file;

	/* todo: si_xino_expire and the ratio should be customizable */
	sbinfo = au_sbi(sb);
	if (time_before(jiffies,
			sbinfo->si_xino_jiffy + sbinfo->si_xino_expire))
		return 0;

	/* truncation border */
	file = au_xino_file(br);
	AuDebugOn(!file);
	err = vfs_statfs(&file->f_path, &st);
	if (unlikely(err)) {
		AuErr1("statfs err %d, ignored\n", err);
		return 0;
	}
	if (div64_u64(st.f_bfree * 100, st.f_blocks) >= AUFS_XINO_DEF_TRUNC)
		return 0;

	return 1;
}

static void xino_try_trunc(struct super_block *sb, struct au_branch *br)
{
	struct xino_do_trunc_args *args;
	int wkq_err;

	if (!xino_trunc_test(sb, br))
		return;

	if (atomic_inc_return(&br->br_xino->xi_truncating) > 1)
		goto out;

	/* lock and kfree() will be called in trunc_xino() */
	args = kmalloc(sizeof(*args), GFP_NOFS);
	if (unlikely(!args)) {
		AuErr1("no memory\n");
		goto out;
	}

	au_br_get(br);
	args->sb = sb;
	args->br = br;
	wkq_err = au_wkq_nowait(xino_do_trunc, args, sb, /*flags*/0);
	if (!wkq_err)
		return; /* success */

	pr_err("wkq %d\n", wkq_err);
	au_br_put(br);
	kfree(args);

out:
	atomic_dec(&br->br_xino->xi_truncating);
}

/* ---------------------------------------------------------------------- */

/*
 * read @ino from xinofile for the specified branch{@sb, @bindex}
 * at the position of @h_ino.
 */
int au_xino_read(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
		 ino_t *ino)
{
	int err;
	ssize_t sz;
	loff_t pos;
	struct au_branch *br;
	struct file *file;
	struct au_sbinfo *sbinfo;

	*ino = 0;
	if (!au_opt_test(au_mntflags(sb), XINO))
		return 0; /* no xino */

	err = 0;
	sbinfo = au_sbi(sb);
	pos = h_ino;
	if (unlikely(au_loff_max / sizeof(*ino) - 1 < pos)) {
		AuIOErr1("too large hi%lu\n", (unsigned long)h_ino);
		return -EFBIG;
	}
	pos *= sizeof(*ino);

	br = au_sbr(sb, bindex);
	file = au_xino_file(br);
	if (vfsub_f_size_read(file) < pos + sizeof(*ino))
		return 0; /* no ino */

	sz = xino_fread(sbinfo->si_xread, file, ino, sizeof(*ino), &pos);
	if (sz == sizeof(*ino))
		return 0; /* success */

	err = sz;
	if (unlikely(sz >= 0)) {
		err = -EIO;
		AuIOErr("xino read error (%zd)\n", sz);
	}

	return err;
}

static int au_xino_do_write(vfs_writef_t write, struct file *file,
			    ino_t h_ino, ino_t ino)
{
	loff_t pos;
	ssize_t sz;

	pos = h_ino;
	if (unlikely(au_loff_max / sizeof(ino) - 1 < pos)) {
		AuIOErr1("too large hi%lu\n", (unsigned long)h_ino);
		return -EFBIG;
	}
	pos *= sizeof(ino);
	sz = xino_fwrite(write, file, &ino, sizeof(ino), &pos);
	if (sz == sizeof(ino))
		return 0; /* success */

	AuIOErr("write failed (%zd)\n", sz);
	return -EIO;
}

/*
 * write @ino to the xinofile for the specified branch{@sb, @bindex}
 * at the position of @h_ino.
 * even if @ino is zero, it is written to the xinofile and means no entry.
 * if the size of the xino file on a specific filesystem exceeds the watermark,
 * try truncating it.
 */
int au_xino_write(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
		  ino_t ino)
{
	int err;
	unsigned int mnt_flags;
	struct au_branch *br;

	BUILD_BUG_ON(sizeof(long long) != sizeof(au_loff_max)
		     || ((loff_t)-1) > 0);
	SiMustAnyLock(sb);

	mnt_flags = au_mntflags(sb);
	if (!au_opt_test(mnt_flags, XINO))
		return 0;

	br = au_sbr(sb, bindex);
	err = au_xino_do_write(au_sbi(sb)->si_xwrite, au_xino_file(br), h_ino,
			       ino);
	if (!err) {
		if (au_opt_test(mnt_flags, TRUNC_XINO)
		    && au_test_fs_trunc_xino(au_br_sb(br)))
			xino_try_trunc(sb, br);
		return 0; /* success */
	}

	AuIOErr("write failed (%d)\n", err);
	return -EIO;
}

static ssize_t xino_fread_wkq(vfs_readf_t func, struct file *file, void *buf,
			      size_t size, loff_t *pos);

/* todo: unnecessary to support mmap_sem since kernel-space? */
ssize_t xino_fread(vfs_readf_t func, struct file *file, void *kbuf, size_t size,
		   loff_t *pos)
{
	ssize_t err;
	mm_segment_t oldfs;
	union {
		void *k;
		char __user *u;
	} buf;
	int i;
	const int prevent_endless = 10;

	i = 0;
	buf.k = kbuf;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	do {
		err = func(file, buf.u, size, pos);
		if (err == -EINTR
		    && !au_wkq_test()
		    && fatal_signal_pending(current)) {
			set_fs(oldfs);
			err = xino_fread_wkq(func, file, kbuf, size, pos);
			BUG_ON(err == -EINTR);
			oldfs = get_fs();
			set_fs(KERNEL_DS);
		}
	} while (i++ < prevent_endless
		 && (err == -EAGAIN || err == -EINTR));
	set_fs(oldfs);

#if 0 /* reserved for future use */
	if (err > 0)
		fsnotify_access(file->f_path.dentry);
#endif

	return err;
}

struct xino_fread_args {
	ssize_t *errp;
	vfs_readf_t func;
	struct file *file;
	void *buf;
	size_t size;
	loff_t *pos;
};

static void call_xino_fread(void *args)
{
	struct xino_fread_args *a = args;
	*a->errp = xino_fread(a->func, a->file, a->buf, a->size, a->pos);
}

static ssize_t xino_fread_wkq(vfs_readf_t func, struct file *file, void *buf,
			      size_t size, loff_t *pos)
{
	ssize_t err;
	int wkq_err;
	struct xino_fread_args args = {
		.errp	= &err,
		.func	= func,
		.file	= file,
		.buf	= buf,
		.size	= size,
		.pos	= pos
	};

	wkq_err = au_wkq_wait(call_xino_fread, &args);
	if (unlikely(wkq_err))
		err = wkq_err;

	return err;
}

static ssize_t xino_fwrite_wkq(vfs_writef_t func, struct file *file, void *buf,
			       size_t size, loff_t *pos);

static ssize_t do_xino_fwrite(vfs_writef_t func, struct file *file, void *kbuf,
			      size_t size, loff_t *pos)
{
	ssize_t err;
	mm_segment_t oldfs;
	union {
		void *k;
		const char __user *u;
	} buf;
	int i;
	const int prevent_endless = 10;

	i = 0;
	buf.k = kbuf;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	do {
		err = func(file, buf.u, size, pos);
		if (err == -EINTR
		    && !au_wkq_test()
		    && fatal_signal_pending(current)) {
			set_fs(oldfs);
			err = xino_fwrite_wkq(func, file, kbuf, size, pos);
			BUG_ON(err == -EINTR);
			oldfs = get_fs();
			set_fs(KERNEL_DS);
		}
	} while (i++ < prevent_endless
		 && (err == -EAGAIN || err == -EINTR));
	set_fs(oldfs);

#if 0 /* reserved for future use */
	if (err > 0)
		fsnotify_modify(file->f_path.dentry);
#endif

	return err;
}

struct do_xino_fwrite_args {
	ssize_t *errp;
	vfs_writef_t func;
	struct file *file;
	void *buf;
	size_t size;
	loff_t *pos;
};

static void call_do_xino_fwrite(void *args)
{
	struct do_xino_fwrite_args *a = args;
	*a->errp = do_xino_fwrite(a->func, a->file, a->buf, a->size, a->pos);
}

static ssize_t xino_fwrite_wkq(vfs_writef_t func, struct file *file, void *buf,
			       size_t size, loff_t *pos)
{
	ssize_t err;
	int wkq_err;
	struct do_xino_fwrite_args args = {
		.errp	= &err,
		.func	= func,
		.file	= file,
		.buf	= buf,
		.size	= size,
		.pos	= pos
	};

	/*
	 * it breaks RLIMIT_FSIZE and normal user's limit,
	 * users should care about quota and real 'filesystem full.'
	 */
	wkq_err = au_wkq_wait(call_do_xino_fwrite, &args);
	if (unlikely(wkq_err))
		err = wkq_err;

	return err;
}

ssize_t xino_fwrite(vfs_writef_t func, struct file *file, void *buf,
		    size_t size, loff_t *pos)
{
	ssize_t err;

	if (rlimit(RLIMIT_FSIZE) == RLIM_INFINITY) {
		lockdep_off();
		err = do_xino_fwrite(func, file, buf, size, pos);
		lockdep_on();
	} else {
		lockdep_off();
		err = xino_fwrite_wkq(func, file, buf, size, pos);
		lockdep_on();
	}

	return err;
}

/* ---------------------------------------------------------------------- */

/*
 * inode number bitmap
 */
static const int page_bits = (int)PAGE_SIZE * BITS_PER_BYTE;
static ino_t xib_calc_ino(unsigned long pindex, int bit)
{
	ino_t ino;

	AuDebugOn(bit < 0 || page_bits <= bit);
	ino = AUFS_FIRST_INO + pindex * page_bits + bit;
	return ino;
}

static void xib_calc_bit(ino_t ino, unsigned long *pindex, int *bit)
{
	AuDebugOn(ino < AUFS_FIRST_INO);
	ino -= AUFS_FIRST_INO;
	*pindex = ino / page_bits;
	*bit = ino % page_bits;
}

static int xib_pindex(struct super_block *sb, unsigned long pindex)
{
	int err;
	loff_t pos;
	ssize_t sz;
	struct au_sbinfo *sbinfo;
	struct file *xib;
	unsigned long *p;

	sbinfo = au_sbi(sb);
	MtxMustLock(&sbinfo->si_xib_mtx);
	AuDebugOn(pindex > ULONG_MAX / PAGE_SIZE
		  || !au_opt_test(sbinfo->si_mntflags, XINO));

	if (pindex == sbinfo->si_xib_last_pindex)
		return 0;

	xib = sbinfo->si_xib;
	p = sbinfo->si_xib_buf;
	pos = sbinfo->si_xib_last_pindex;
	pos *= PAGE_SIZE;
	sz = xino_fwrite(sbinfo->si_xwrite, xib, p, PAGE_SIZE, &pos);
	if (unlikely(sz != PAGE_SIZE))
		goto out;

	pos = pindex;
	pos *= PAGE_SIZE;
	if (vfsub_f_size_read(xib) >= pos + PAGE_SIZE)
		sz = xino_fread(sbinfo->si_xread, xib, p, PAGE_SIZE, &pos);
	else {
		memset(p, 0, PAGE_SIZE);
		sz = xino_fwrite(sbinfo->si_xwrite, xib, p, PAGE_SIZE, &pos);
	}
	if (sz == PAGE_SIZE) {
		sbinfo->si_xib_last_pindex = pindex;
		return 0; /* success */
	}

out:
	AuIOErr1("write failed (%zd)\n", sz);
	err = sz;
	if (sz >= 0)
		err = -EIO;
	return err;
}

static void au_xib_clear_bit(struct inode *inode)
{
	int err, bit;
	unsigned long pindex;
	struct super_block *sb;
	struct au_sbinfo *sbinfo;

	AuDebugOn(inode->i_nlink);

	sb = inode->i_sb;
	xib_calc_bit(inode->i_ino, &pindex, &bit);
	AuDebugOn(page_bits <= bit);
	sbinfo = au_sbi(sb);
	mutex_lock(&sbinfo->si_xib_mtx);
	err = xib_pindex(sb, pindex);
	if (!err) {
		clear_bit(bit, sbinfo->si_xib_buf);
		sbinfo->si_xib_next_bit = bit;
	}
	mutex_unlock(&sbinfo->si_xib_mtx);
}

/* ---------------------------------------------------------------------- */

/*
 * truncate a xino bitmap file
 */

/* todo: slow */
static int do_xib_restore(struct super_block *sb, struct file *file, void *page)
{
	int err, bit;
	ssize_t sz;
	unsigned long pindex;
	loff_t pos, pend;
	struct au_sbinfo *sbinfo;
	vfs_readf_t func;
	ino_t *ino;
	unsigned long *p;

	err = 0;
	sbinfo = au_sbi(sb);
	MtxMustLock(&sbinfo->si_xib_mtx);
	p = sbinfo->si_xib_buf;
	func = sbinfo->si_xread;
	pend = vfsub_f_size_read(file);
	pos = 0;
	while (pos < pend) {
		sz = xino_fread(func, file, page, PAGE_SIZE, &pos);
		err = sz;
		if (unlikely(sz <= 0))
			goto out;

		err = 0;
		for (ino = page; sz > 0; ino++, sz -= sizeof(ino)) {
			if (unlikely(*ino < AUFS_FIRST_INO))
				continue;

			xib_calc_bit(*ino, &pindex, &bit);
			AuDebugOn(page_bits <= bit);
			err = xib_pindex(sb, pindex);
			if (!err)
				set_bit(bit, p);
			else
				goto out;
		}
	}

out:
	return err;
}

static int xib_restore(struct super_block *sb)
{
	int err;
	aufs_bindex_t bindex, bbot;
	void *page;
	struct au_branch *br;

	err = -ENOMEM;
	page = (void *)__get_free_page(GFP_NOFS);
	if (unlikely(!page))
		goto out;

	err = 0;
	bbot = au_sbbot(sb);
	for (bindex = 0; !err && bindex <= bbot; bindex++)
		if (!bindex || is_sb_shared(sb, bindex, bindex - 1) < 0) {
			br = au_sbr(sb, bindex);
			err = do_xib_restore(sb, au_xino_file(br), page);
		} else
			AuDbg("skip shared b%d\n", bindex);
	free_page((unsigned long)page);

out:
	return err;
}

int au_xib_trunc(struct super_block *sb)
{
	int err;
	ssize_t sz;
	loff_t pos;
	struct au_sbinfo *sbinfo;
	unsigned long *p;
	struct file *file;

	SiMustWriteLock(sb);

	err = 0;
	sbinfo = au_sbi(sb);
	if (!au_opt_test(sbinfo->si_mntflags, XINO))
		goto out;

	file = sbinfo->si_xib;
	if (vfsub_f_size_read(file) <= PAGE_SIZE)
		goto out;

	file = au_xino_create2(sb, &sbinfo->si_xib->f_path, NULL);
	err = PTR_ERR(file);
	if (IS_ERR(file))
		goto out;
	fput(sbinfo->si_xib);
	sbinfo->si_xib = file;

	p = sbinfo->si_xib_buf;
	memset(p, 0, PAGE_SIZE);
	pos = 0;
	sz = xino_fwrite(sbinfo->si_xwrite, sbinfo->si_xib, p, PAGE_SIZE, &pos);
	if (unlikely(sz != PAGE_SIZE)) {
		err = sz;
		AuIOErr("err %d\n", err);
		if (sz >= 0)
			err = -EIO;
		goto out;
	}

	mutex_lock(&sbinfo->si_xib_mtx);
	/* mnt_want_write() is unnecessary here */
	err = xib_restore(sb);
	mutex_unlock(&sbinfo->si_xib_mtx);

out:
	return err;
}

/* ---------------------------------------------------------------------- */

struct au_xino *au_xino_alloc(void)
{
	struct au_xino *xi;

	xi = kzalloc(sizeof(*xi), GFP_NOFS);
	if (unlikely(!xi))
		goto out;

	xi->xi_nondir.total = 8; /* initial size */
	xi->xi_nondir.array = kcalloc(xi->xi_nondir.total, sizeof(ino_t),
				      GFP_NOFS);
	if (unlikely(!xi->xi_nondir.array))
		goto out_free;

	spin_lock_init(&xi->xi_nondir.spin);
	init_waitqueue_head(&xi->xi_nondir.wqh);
	atomic_set(&xi->xi_truncating, 0);
	kref_init(&xi->xi_kref);
	goto out; /* success */

out_free:
	kfree(xi);
	xi = NULL;
out:
	return xi;
}

static int au_xino_init(struct au_branch *br, struct file *file)
{
	int err;
	struct au_xino *xi;

	err = 0;
	xi = au_xino_alloc();
	if (unlikely(!xi)) {
		err = -ENOMEM;
		goto out;
	}

	get_file(file);
	xi->xi_file = file;
	AuDebugOn(br->br_xino);
	br->br_xino = xi;

out:
	return err;
}

static void au_xino_release(struct kref *kref)
{
	struct au_xino *xi;
	int i;

	xi = container_of(kref, struct au_xino, xi_kref);
	if (xi->xi_file)
		fput(xi->xi_file);
	for (i = xi->xi_nondir.total - 1; i >= 0; i--)
		AuDebugOn(xi->xi_nondir.array[i]);
	kfree(xi->xi_nondir.array);
	kfree(xi);
}

int au_xino_put(struct au_branch *br)
{
	int ret;
	struct au_xino *xi;

	ret = 0;
	xi = br->br_xino;
	if (xi) {
		br->br_xino = NULL;
		ret = kref_put(&xi->xi_kref, au_xino_release);
	}

	return ret;
}

void au_xino_file_set(struct au_branch *br, struct file *file)
{
	struct au_xino *xi;
	struct file *f;

	if (file)
		get_file(file);
	xi = br->br_xino;
	AuDebugOn(!xi);
	f = xi->xi_file;
	if (f)
		fput(f);
	xi->xi_file = file;
}

/* ---------------------------------------------------------------------- */

/*
 * xino mount option handlers
 */

/* xino bitmap */
static void xino_clear_xib(struct super_block *sb)
{
	struct au_sbinfo *sbinfo;

	SiMustWriteLock(sb);

	sbinfo = au_sbi(sb);
	/* unnecessary to clear sbinfo->si_xread and ->si_xwrite */
	if (sbinfo->si_xib)
		fput(sbinfo->si_xib);
	sbinfo->si_xib = NULL;
	if (sbinfo->si_xib_buf)
		free_page((unsigned long)sbinfo->si_xib_buf);
	sbinfo->si_xib_buf = NULL;
}

static int au_xino_set_xib(struct super_block *sb, struct path *path)
{
	int err;
	loff_t pos;
	struct au_sbinfo *sbinfo;
	struct file *file;

	SiMustWriteLock(sb);

	sbinfo = au_sbi(sb);
	file = au_xino_create2(sb, path, sbinfo->si_xib);
	err = PTR_ERR(file);
	if (IS_ERR(file))
		goto out;
	if (sbinfo->si_xib)
		fput(sbinfo->si_xib);
	sbinfo->si_xib = file;
	sbinfo->si_xread = vfs_readf(file);
	sbinfo->si_xwrite = vfs_writef(file);

	err = -ENOMEM;
	if (!sbinfo->si_xib_buf)
		sbinfo->si_xib_buf = (void *)get_zeroed_page(GFP_NOFS);
	if (unlikely(!sbinfo->si_xib_buf))
		goto out_unset;

	sbinfo->si_xib_last_pindex = 0;
	sbinfo->si_xib_next_bit = 0;
	if (vfsub_f_size_read(file) < PAGE_SIZE) {
		pos = 0;
		err = xino_fwrite(sbinfo->si_xwrite, file, sbinfo->si_xib_buf,
				  PAGE_SIZE, &pos);
		if (unlikely(err != PAGE_SIZE))
			goto out_free;
	}
	err = 0;
	goto out; /* success */

out_free:
	if (sbinfo->si_xib_buf)
		free_page((unsigned long)sbinfo->si_xib_buf);
	sbinfo->si_xib_buf = NULL;
	if (err >= 0)
		err = -EIO;
out_unset:
	fput(sbinfo->si_xib);
	sbinfo->si_xib = NULL;
out:
	AuTraceErr(err);
	return err;
}

/* xino for each branch */
static void xino_clear_br(struct super_block *sb)
{
	aufs_bindex_t bindex, bbot;
	struct au_branch *br;

	bbot = au_sbbot(sb);
	for (bindex = 0; bindex <= bbot; bindex++) {
		br = au_sbr(sb, bindex);
		AuDebugOn(!br);
		au_xino_put(br);
	}
}

static void au_xino_set_br_shared(struct super_block *sb, struct au_branch *br,
				  aufs_bindex_t bshared)
{
	struct au_branch *brshared;

	brshared = au_sbr(sb, bshared);
	AuDebugOn(!brshared->br_xino);
	AuDebugOn(!brshared->br_xino->xi_file);
	if (br->br_xino != brshared->br_xino) {
		au_xino_get(brshared);
		au_xino_put(br);
		br->br_xino = brshared->br_xino;
	}
}

struct au_xino_do_set_br {
	vfs_writef_t writef;
	struct au_branch *br;
	ino_t h_ino;
	aufs_bindex_t bshared;
};

static int au_xino_do_set_br(struct super_block *sb, struct path *path,
			     struct au_xino_do_set_br *args)
{
	int err;
	struct file *file;

	if (args->bshared >= 0) {
		/* shared xino */
		au_xino_set_br_shared(sb, args->br, args->bshared);
		file = au_xino_file(args->br);
		goto out_ino; /* success */
	}

	/* new xino */
	file = au_xino_create2(sb, path, au_xino_file(args->br));
	err = PTR_ERR(file);
	if (IS_ERR(file))
		goto out;
	if (!args->br->br_xino) {
		err = au_xino_init(args->br, file);
		fput(file);
		if (unlikely(err))
			goto out;
	} else {
		au_xino_file_set(args->br, file);
		fput(file);
	}

out_ino:
	err = au_xino_do_write(args->writef, file, args->h_ino, AUFS_ROOT_INO);
out:
	AuTraceErr(err);
	return err;
}

static int au_xino_set_br(struct super_block *sb, struct path *path)
{
	int err;
	aufs_bindex_t bindex, bbot;
	struct au_xino_do_set_br args;
	struct inode *inode;

	SiMustWriteLock(sb);

	bbot = au_sbbot(sb);
	inode = d_inode(sb->s_root);
	args.writef = au_sbi(sb)->si_xwrite;
	for (bindex = 0; bindex <= bbot; bindex++) {
		args.h_ino = au_h_iptr(inode, bindex)->i_ino;
		args.br = au_sbr(sb, bindex);
		args.bshared = is_sb_shared(sb, bindex, bindex - 1);
		err = au_xino_do_set_br(sb, path, &args);
		if (unlikely(err))
			break;
	}

	AuTraceErr(err);
	return err;
}

void au_xino_clr(struct super_block *sb)
{
	struct au_sbinfo *sbinfo;

	au_xigen_clr(sb);
	xino_clear_xib(sb);
	xino_clear_br(sb);
	dbgaufs_brs_del(sb, 0);
	au_xino_brid_set(sb, -1);
	sbinfo = au_sbi(sb);
	/* lvalue, do not call au_mntflags() */
	au_opt_clr(sbinfo->si_mntflags, XINO);
}

int au_xino_set(struct super_block *sb, struct au_opt_xino *xiopt, int remount)
{
	int err, skip;
	struct dentry *dentry, *parent, *cur_dentry, *cur_parent;
	struct qstr *dname, *cur_name;
	struct file *cur_xino;
	struct au_sbinfo *sbinfo;
	struct path *path, *cur_path;

	SiMustWriteLock(sb);

	err = 0;
	sbinfo = au_sbi(sb);
	path = &xiopt->file->f_path;
	dentry = path->dentry;
	parent = dget_parent(dentry);
	if (remount) {
		skip = 0;
		cur_xino = sbinfo->si_xib;
		if (cur_xino) {
			cur_path = &cur_xino->f_path;
			cur_dentry = cur_path->dentry;
			cur_parent = dget_parent(cur_dentry);
			cur_name = &cur_dentry->d_name;
			dname = &dentry->d_name;
			skip = (cur_parent == parent
				&& au_qstreq(dname, cur_name));
			dput(cur_parent);
		}
		if (skip)
			goto out;
	}

	au_opt_set(sbinfo->si_mntflags, XINO);
	err = au_xino_set_xib(sb, path);
	/* si_x{read,write} are set */
	if (!err)
		err = au_xigen_set(sb, path);
	if (!err)
		err = au_xino_set_br(sb, path);
	if (!err) {
		dbgaufs_brs_add(sb, 0, /*topdown*/1);
		goto out; /* success */
	}

	/* reset all */
	AuIOErr("failed setting xino(%d).\n", err);
	au_xino_clr(sb);

out:
	dput(parent);
	return err;
}

/*
 * create a xinofile at the default place/path.
 */
struct file *au_xino_def(struct super_block *sb)
{
	struct file *file;
	char *page, *p;
	struct au_branch *br;
	struct super_block *h_sb;
	struct path path;
	aufs_bindex_t bbot, bindex, bwr;

	br = NULL;
	bbot = au_sbbot(sb);
	bwr = -1;
	for (bindex = 0; bindex <= bbot; bindex++) {
		br = au_sbr(sb, bindex);
		if (au_br_writable(br->br_perm)
		    && !au_test_fs_bad_xino(au_br_sb(br))) {
			bwr = bindex;
			break;
		}
	}

	if (bwr >= 0) {
		file = ERR_PTR(-ENOMEM);
		page = (void *)__get_free_page(GFP_NOFS);
		if (unlikely(!page))
			goto out;
		path.mnt = au_br_mnt(br);
		path.dentry = au_h_dptr(sb->s_root, bwr);
		p = d_path(&path, page, PATH_MAX - sizeof(AUFS_XINO_FNAME));
		file = (void *)p;
		if (!IS_ERR(p)) {
			strcat(p, "/" AUFS_XINO_FNAME);
			AuDbg("%s\n", p);
			file = au_xino_create(sb, p, /*silent*/0);
			if (!IS_ERR(file))
				au_xino_brid_set(sb, br->br_id);
		}
		free_page((unsigned long)page);
	} else {
		file = au_xino_create(sb, AUFS_XINO_DEFPATH, /*silent*/0);
		if (IS_ERR(file))
			goto out;
		h_sb = file->f_path.dentry->d_sb;
		if (unlikely(au_test_fs_bad_xino(h_sb))) {
			pr_err("xino doesn't support %s(%s)\n",
			       AUFS_XINO_DEFPATH, au_sbtype(h_sb));
			fput(file);
			file = ERR_PTR(-EINVAL);
		}
		if (!IS_ERR(file))
			au_xino_brid_set(sb, -1);
	}

out:
	return file;
}

/* ---------------------------------------------------------------------- */

/*
 * initialize the xinofile for the specified branch @br
 * at the place/path where @base_file indicates.
 * test whether another branch is on the same filesystem or not,
 * if found then share the xinofile with another branch.
 */
int au_xino_init_br(struct super_block *sb, struct au_branch *br, ino_t h_ino,
		    struct path *base)
{
	int err;
	struct au_xino_do_set_br args = {
		.h_ino	= h_ino,
		.br	= br
	};

	args.writef = au_sbi(sb)->si_xwrite;
	args.bshared = sbr_find_shared(sb, /*btop*/0, au_sbbot(sb),
				       au_br_sb(br));
	err = au_xino_do_set_br(sb, base, &args);
	if (unlikely(err))
		au_xino_put(br);

	return err;
}

/* ---------------------------------------------------------------------- */

/*
 * get an unused inode number from bitmap
 */
ino_t au_xino_new_ino(struct super_block *sb)
{
	ino_t ino;
	unsigned long *p, pindex, ul, pend;
	struct au_sbinfo *sbinfo;
	struct file *file;
	int free_bit, err;

	if (!au_opt_test(au_mntflags(sb), XINO))
		return iunique(sb, AUFS_FIRST_INO);

	sbinfo = au_sbi(sb);
	mutex_lock(&sbinfo->si_xib_mtx);
	p = sbinfo->si_xib_buf;
	free_bit = sbinfo->si_xib_next_bit;
	if (free_bit < page_bits && !test_bit(free_bit, p))
		goto out; /* success */
	free_bit = find_first_zero_bit(p, page_bits);
	if (free_bit < page_bits)
		goto out; /* success */

	pindex = sbinfo->si_xib_last_pindex;
	for (ul = pindex - 1; ul < ULONG_MAX; ul--) {
		err = xib_pindex(sb, ul);
		if (unlikely(err))
			goto out_err;
		free_bit = find_first_zero_bit(p, page_bits);
		if (free_bit < page_bits)
			goto out; /* success */
	}

	file = sbinfo->si_xib;
	pend = vfsub_f_size_read(file) / PAGE_SIZE;
	for (ul = pindex + 1; ul <= pend; ul++) {
		err = xib_pindex(sb, ul);
		if (unlikely(err))
			goto out_err;
		free_bit = find_first_zero_bit(p, page_bits);
		if (free_bit < page_bits)
			goto out; /* success */
	}
	BUG();

out:
	set_bit(free_bit, p);
	sbinfo->si_xib_next_bit = free_bit + 1;
	pindex = sbinfo->si_xib_last_pindex;
	mutex_unlock(&sbinfo->si_xib_mtx);
	ino = xib_calc_ino(pindex, free_bit);
	AuDbg("i%lu\n", (unsigned long)ino);
	return ino;
out_err:
	mutex_unlock(&sbinfo->si_xib_mtx);
	AuDbg("i0\n");
	return 0;
}

/* for s_op->delete_inode() */
void au_xino_delete_inode(struct inode *inode, const int unlinked)
{
	int err;
	unsigned int mnt_flags;
	aufs_bindex_t bindex, bbot, bi;
	unsigned char try_trunc;
	struct au_iinfo *iinfo;
	struct super_block *sb;
	struct au_hinode *hi;
	struct inode *h_inode;
	struct au_branch *br;
	vfs_writef_t xwrite;

	AuDebugOn(au_is_bad_inode(inode));

	sb = inode->i_sb;
	mnt_flags = au_mntflags(sb);
	if (!au_opt_test(mnt_flags, XINO)
	    || inode->i_ino == AUFS_ROOT_INO)
		return;

	if (unlinked) {
		au_xigen_inc(inode);
		au_xib_clear_bit(inode);
	}

	iinfo = au_ii(inode);
	bindex = iinfo->ii_btop;
	if (bindex < 0)
		return;

	xwrite = au_sbi(sb)->si_xwrite;
	try_trunc = !!au_opt_test(mnt_flags, TRUNC_XINO);
	hi = au_hinode(iinfo, bindex);
	bbot = iinfo->ii_bbot;
	for (; bindex <= bbot; bindex++, hi++) {
		h_inode = hi->hi_inode;
		if (!h_inode
		    || (!unlinked && h_inode->i_nlink))
			continue;

		/* inode may not be revalidated */
		bi = au_br_index(sb, hi->hi_id);
		if (bi < 0)
			continue;

		br = au_sbr(sb, bi);
		err = au_xino_do_write(xwrite, au_xino_file(br),
				       h_inode->i_ino, /*ino*/0);
		if (!err && try_trunc
		    && au_test_fs_trunc_xino(au_br_sb(br)))
			xino_try_trunc(sb, br);
	}
}

/* ---------------------------------------------------------------------- */

static int au_xinondir_find(struct au_xino *xi, ino_t h_ino)
{
	int found, total, i;

	found = -1;
	total = xi->xi_nondir.total;
	for (i = 0; i < total; i++) {
		if (xi->xi_nondir.array[i] != h_ino)
			continue;
		found = i;
		break;
	}

	return found;
}

static int au_xinondir_expand(struct au_xino *xi)
{
	int err, sz;
	ino_t *p;

	BUILD_BUG_ON(KMALLOC_MAX_SIZE > INT_MAX);

	err = -ENOMEM;
	sz = xi->xi_nondir.total * sizeof(ino_t);
	if (unlikely(sz > KMALLOC_MAX_SIZE / 2))
		goto out;
	p = au_kzrealloc(xi->xi_nondir.array, sz, sz << 1, GFP_ATOMIC,
			 /*may_shrink*/0);
	if (p) {
		xi->xi_nondir.array = p;
		xi->xi_nondir.total <<= 1;
		AuDbg("xi_nondir.total %d\n", xi->xi_nondir.total);
		err = 0;
	}

out:
	return err;
}

void au_xinondir_leave(struct super_block *sb, aufs_bindex_t bindex,
		       ino_t h_ino, int idx)
{
	struct au_xino *xi;

	AuDebugOn(!au_opt_test(au_mntflags(sb), XINO));
	xi = au_sbr(sb, bindex)->br_xino;
	AuDebugOn(idx < 0 || xi->xi_nondir.total <= idx);

	spin_lock(&xi->xi_nondir.spin);
	AuDebugOn(xi->xi_nondir.array[idx] != h_ino);
	xi->xi_nondir.array[idx] = 0;
	spin_unlock(&xi->xi_nondir.spin);
	wake_up_all(&xi->xi_nondir.wqh);
}

int au_xinondir_enter(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
		      int *idx)
{
	int err, found, empty;
	struct au_xino *xi;

	err = 0;
	*idx = -1;
	if (!au_opt_test(au_mntflags(sb), XINO))
		goto out; /* no xino */

	xi = au_sbr(sb, bindex)->br_xino;

again:
	spin_lock(&xi->xi_nondir.spin);
	found = au_xinondir_find(xi, h_ino);
	if (found == -1) {
		empty = au_xinondir_find(xi, /*h_ino*/0);
		if (empty == -1) {
			empty = xi->xi_nondir.total;
			err = au_xinondir_expand(xi);
			if (unlikely(err))
				goto out_unlock;
		}
		xi->xi_nondir.array[empty] = h_ino;
		*idx = empty;
	} else {
		spin_unlock(&xi->xi_nondir.spin);
		wait_event(xi->xi_nondir.wqh,
			   xi->xi_nondir.array[found] != h_ino);
		goto again;
	}

out_unlock:
	spin_unlock(&xi->xi_nondir.spin);
out:
	return err;
}

/* ---------------------------------------------------------------------- */

int au_xino_path(struct seq_file *seq, struct file *file)
{
	int err;

	err = au_seq_path(seq, &file->f_path);
	if (unlikely(err))
		goto out;

#define Deleted "\\040(deleted)"
	seq->count -= sizeof(Deleted) - 1;
	AuDebugOn(memcmp(seq->buf + seq->count, Deleted,
			 sizeof(Deleted) - 1));
#undef Deleted

out:
	return err;
}
