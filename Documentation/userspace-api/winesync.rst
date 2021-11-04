=====================================
Wine synchronization primitive driver
=====================================

This page documents the user-space API for the winesync driver.

winesync is a support driver for emulation of NT synchronization
primitives by the Wine project. It exists because implementation in
user-space, using existing tools, cannot satisfy performance,
correctness, and security constraints. It is implemented entirely in
software, and does not drive any hardware device.

This interface is meant as a compatibility tool only and should not be
used for general synchronization; instead use generic, versatile
interfaces such as futex(2) and poll(2).

Synchronization primitives
==========================

The winesync driver exposes two types of synchronization primitives,
semaphores and mutexes.

A semaphore holds a single volatile 32-bit counter, and a static
32-bit integer denoting the maximum value. It is considered signaled
when the counter is nonzero. The counter is decremented by one when a
wait is satisfied. Both the initial and maximum count are established
when the semaphore is created.

A mutex holds a volatile 32-bit recursion count, and a volatile 32-bit
identifier denoting its owner. The latter is intended to identify the
thread holding the mutex; however, it is not actually validated
against earlier calls made by the same thread. A mutex is considered
signaled when its owner is zero (indicating that it is not owned). The
recursion count is incremented when a wait is satisfied, and ownership
is set to the given identifier. A mutex also holds an internal flag
denoting whether its previous owner has died; such a mutex is said to
be inconsistent. Owner death is not tracked automatically based on
thread death, but rather must be communicated using
``WINESYNC_IOC_KILL_OWNER``.

Objects are represented by signed 32-bit integers. A valid object
identifier will always be nonnegative.

Char device
===========

The winesync driver creates a single char device /dev/winesync. Each
file description opened on the device represents a unique namespace.
That is, objects created on one open file description are shared
across all its individual descriptors, but are not shared with other
open() calls on the same device.

ioctl reference
===============

All operations on the device are done through ioctls. There are three
structures used in ioctl calls::

   struct winesync_sem_args {
	__s32 sem;
	__u32 count;
	__u32 max;
	__u32 flags;
   };

   struct winesync_mutex_args {
	__s32 mutex;
	__u32 owner;
	__u32 count;
   };

   struct winesync_wait_args {
	__u64 timeout;
	__u64 objs;
	__u32 count;
	__u32 owner;
	__u32 index;
	__u32 pad;
   };

Depending on the ioctl, members of the structure may be used as input,
output, or not at all.

All ioctls return 0 on success, and -1 on error, in which case `errno`
will be set to a nonzero error code.

The ioctls are as follows:

.. c:macro:: WINESYNC_IOC_CREATE_SEM

  Create a semaphore object. Takes a pointer to struct
  :c:type:`winesync_sem_args`, which is used as follows:

    ``count`` and ``max`` are input-only arguments, denoting the
    initial and maximum count of the semaphore.

    ``flags`` is an input-only argument, which specifies additional
    flags modifying the behaviour of the semaphore. There is only one
    flag defined, ``WINESYNC_SEM_GETONWAIT``. If present, wait
    operations on this semaphore will acquire it, decrementing its
    count by one; otherwise, wait operations will not affect the
    semaphore's state.

    ``sem`` is an output-only argument, which will be filled with the
    allocated identifier if successful.

  Fails with ``EINVAL`` if ``count`` is greater than ``max``, or
  ``ENOMEM`` if not enough memory is available.

.. c:macro:: WINESYNC_IOC_CREATE_MUTEX

  Create a mutex object. Takes a pointer to struct
  :c:type:`winesync_mutex_args`, which is used as follows:

    ``owner`` is an input-only argument denoting the initial owner of
    the mutex.

    ``count`` is an input-only argument denoting the initial recursion
    count of the mutex. If ``owner`` is nonzero and ``count`` is zero,
    or if ``owner`` is zero and ``count`` is nonzero, the function
    fails with ``EINVAL``.

    ``mutex`` is an output-only argument, which will be filled with
    the allocated identifier if successful.

  Fails with ``ENOMEM`` if not enough memory is available.

.. c:macro:: WINESYNC_IOC_DELETE

  Delete an object of any type. Takes an input-only pointer to a
  32-bit integer denoting the object to delete. Fails with ``EINVAL``
  if the object is not valid. Further ioctls attempting to use the
  object return ``EINVAL``, unless the object identifier is reused.
  However, wait ioctls currently in progress are not interrupted, and
  behave as if the object remains valid.

.. c:macro:: WINESYNC_IOC_PUT_SEM

  Post to a semaphore object. Takes a pointer to struct
  :c:type:`winesync_sem_args`, which is used as follows:

    ``sem`` is an input-only argument denoting the semaphore object.
    If ``sem`` is not a valid semaphore object, the ioctl fails with
    ``EINVAL``.

    ``count`` contains on input the count to add to the semaphore, and
    on output is filled with its previous count.

    ``max`` and ``flags`` are not used.

  The operation is atomic and totally ordered with respect to other
  operations on the same semaphore. If adding ``count`` to the
  semaphore's current count would raise the latter past the
  semaphore's maximum count, the ioctl fails with ``EOVERFLOW`` and
  the semaphore is not affected. If raising the semaphore's count
  causes it to become signaled, eligible threads waiting on this
  semaphore will be woken and the semaphore's count decremented
  appropriately.

.. c:macro:: WINESYNC_IOC_PULSE_SEM

  This operation is identical to ``WINESYNC_IOC_PUT_SEM``, with one
  notable exception: the semaphore is always left in an *unsignaled*
  state, regardless of the initial count or the count added by the
  ioctl. That is, the count after a pulse operation will always be
  zero. The entire operation is atomic.

  Hence, if the semaphore was created with the
  ``WINESYNC_SEM_GETONWAIT`` flag set, and an unsignaled semaphore is
  "pulsed" with a count of 2, at most two eligible threads (i.e.
  threads not otherwise constrained due to ``WINESYNC_IOC_WAIT_ALL``)
  will be woken up, and any others will remain sleeping. If less than
  two eligible threads are waiting on the semaphore, all of them will
  be woken up, and the semaphore's count will remain at zero. On the
  other hand, if the semaphore was created without the
  ``WINESYNC_SEM_GETONWAIT``, all eligible threads will be woken up,
  making ``count`` effectively redundant. In either case, a
  simultaneous ``WINESYNC_IOC_READ_SEM`` ioctl from another thread
  will always report a count of zero.

  If adding ``count`` to the semaphore's current count would raise the
  latter past the semaphore's maximum count, the ioctl fails with
  ``EOVERFLOW``. However, in this case the semaphore's count will
  still be reset to zero.

.. c:macro:: WINESYNC_IOC_GET_SEM

  Attempt to acquire a semaphore object. Takes an input-only pointer
  to a 32-bit integer denoting the semaphore to acquire.

  This operation does not block. If the semaphore's count was zero, it
  fails with ``EWOULDBLOCK``. Otherwise, the semaphore's count is
  decremented by one. The behaviour of this operation is unaffected by
  whether the semaphore was created with the
  ``WINESYNC_SEM_GETONWAIT`` flag set.

  The operation is atomic and totally ordered with respect to other
  operations on the same semaphore.

.. c:macro:: WINESYNC_IOC_PUT_MUTEX

  Release a mutex object. Takes a pointer to struct
  :c:type:`winesync_mutex_args`, which is used as follows:

    ``mutex`` is an input-only argument denoting the mutex object. If
    ``mutex`` is not a valid mutex object, the ioctl fails with
    ``EINVAL``.

    ``owner`` is an input-only argument denoting the mutex owner.
    ``owner`` must be nonzero, else the ioctl fails with ``EINVAL``.
    If ``owner`` is not the current owner of the mutex, the ioctl
    fails with ``EPERM``.

    ``count`` is an output-only argument which will be filled on
    success with the mutex's previous recursion count.

  The mutex's count will be decremented by one. The operation is
  atomic and totally ordered with respect to other operations on the
  same mutex. If decrementing the mutex's count causes it to become
  zero, the mutex is marked as unowned and signaled, and eligible
  threads waiting on it will be woken as appropriate.

.. c:macro:: WINESYNC_IOC_READ_SEM

  Read the current state of a semaphore object. Takes a pointer to
  struct :c:type:`winesync_sem_args`, which is used as follows:

    ``sem`` is an input-only argument denoting the semaphore object.
    If ``sem`` is not a valid semaphore object, the ioctl fails with
    ``EINVAL``.

    ``count`` and ``max`` are output-only arguments, which will be
    filled with the current and maximum count of the given semaphore.

    ``flags`` is an output-only argument, which will be filled with
    the flags used to create the semaphore.

  The operation is atomic and totally ordered with respect to other
  operations on the same semaphore.

.. c:macro:: WINESYNC_IOC_READ_MUTEX

  Read the current state of a mutex object. Takes a pointer to struct
  :c:type:`winesync_mutex_args`, which is used as follows:

    ``mutex`` is an input-only argument denoting the mutex object. If
    ``mutex`` is not a valid mutex object, the ioctl fails with
    ``EINVAL``.

    ``count`` and ``owner`` are output-only arguments, which will be
    filled with the current recursion count and owner of the given
    mutex. If the mutex is not owned, both ``count`` and ``owner`` are
    set to zero.

  If the mutex is marked as inconsistent, the function fails with
  ``EOWNERDEAD``.

  The operation is atomic and totally ordered with respect to other
  operations on the same mutex.

.. c:macro:: WINESYNC_IOC_KILL_OWNER

  Mark any mutexes owned by the given identifier as unowned and
  inconsistent. Takes an input-only pointer to a 32-bit integer
  denoting the owner. If the owner is zero, the ioctl fails with
  ``EINVAL``.

.. c:macro:: WINESYNC_IOC_WAIT_ANY

  Poll on any of a list of objects, atomically acquiring (at most)
  one. Takes a pointer to struct :c:type:`winesync_wait_args`, which
  is used as follows:

    ``timeout`` is an optional input-only pointer to a 64-bit struct
    :c:type:`timespec` (specified as an integer so that the structure
    has the same size regardless of architecture). The timeout is
    specified in absolute format, as measured against the MONOTONIC
    clock. If the timeout is equal to or earlier than the current
    time, the function returns immediately without sleeping. If
    ``timeout`` is zero, i.e. NULL, the function will sleep until an
    object is signaled, and will not fail with ``ETIMEDOUT``.

    ``objs`` is a input-only pointer to an array of ``count`` 32-bit
    object identifiers (specified as an integer so that the structure
    has the same size regardless of architecture). If any identifier
    is invalid, the function fails with ``EINVAL``.

    ``count`` is an input-only argument denoting the number of
    elements in ``objs``.

    ``owner`` is an input-only argument denoting the mutex owner
    identifier. If any object in ``objs`` is a mutex, the ioctl will
    attempt to acquire that mutex on behalf of ``owner``. If ``owner``
    is zero, the ioctl fails with ``EINVAL``.

    ``index`` is an output-only argument which, if the ioctl is
    successful, is filled with the index of the object actually
    signaled.

    ``pad`` is unused, and exists to keep a consistent structure size.

  This function attempts to acquire one of the given objects. If
  unable to do so, it sleeps until an object becomes signaled,
  subsequently acquiring it, or the timeout expires. In the latter
  case the ioctl fails with ``ETIMEDOUT``. The function only acquires
  one object, even if multiple objects are signaled.

  A semaphore is considered to be signaled if its count is nonzero. It
  is acquired by decrementing its count by one if the
  ``WINESYNC_SEM_GETONWAIT`` flag was used to create it; otherwise no
  operation is done to acquire the semaphore. A mutex is considered to
  be signaled if it is unowned or if its owner matches the ``owner``
  argument, and is acquired by incrementing its recursion count by one
  and setting its owner to the ``owner`` argument.

  Acquisition is atomic and totally ordered with respect to other
  operations on the same object. If two wait operations (with
  different ``owner`` identifiers) are queued on the same mutex, only
  one is signaled. If two wait operations are queued on the same
  semaphore (which was not created with the ``WINESYNC_SEM_GETONWAIT``
  flag set), and a value of one is posted to it, only one is signaled.
  The order in which threads are signaled is not guaranteed.

  (If two wait operations are queued on the same semaphore, and the
  semaphore was created with the ``WINESYNC_SEM_GETONWAIT`` flag set,
  and a value of one is posted to it, both threads are signaled, and
  the semaphore retains a count of one.)

  If an inconsistent mutex is acquired, the ioctl fails with
  ``EOWNERDEAD``. Although this is a failure return, the function may
  otherwise be considered successful. The mutex is marked as owned by
  the given owner (with a recursion count of 1) and as no longer
  inconsistent. ``index`` is still set to the index of the mutex.

  Unlike ``WINESYNC_IOC_WAIT_ALL``, it is valid to pass the same
  object more than once. If a wakeup occurs due to that object being
  signaled, ``index`` is set to the index of the first instance of the
  object.

  Fails with ``ENOMEM`` if not enough memory is available, or
  ``EINTR`` if a signal is received.

.. c:macro:: WINESYNC_IOC_WAIT_ALL

  Poll on a list of objects, atomically acquiring all of them. Takes a
  pointer to struct :c:type:`winesync_wait_args`, which is used
  identically to ``WINESYNC_IOC_WAIT_ANY``, except that ``index`` is
  unused.

  This function attempts to simultaneously acquire all of the given
  objects. If unable to do so, it sleeps until all objects become
  simultaneously signaled, subsequently acquiring them, or the timeout
  expires. In the latter case the ioctl fails with ``ETIMEDOUT`` and
  no objects are modified.

  Objects may become signaled and subsequently designaled (through
  acquisition by other threads) while this thread is sleeping. Only
  once all objects are simultaneously signaled does the ioctl return.
  The acquisition is atomic and totally ordered with respect to other
  operations on any of the given objects.

  If an inconsistent mutex is acquired, the ioctl fails with
  ``EOWNERDEAD``. Similarly to ``WINESYNC_IOC_WAIT_ANY``, all objects
  are nevertheless marked as acquired. Note that if multiple mutex
  objects are specified, there is no way to know which were marked as
  inconsistent.

  Unlike ``WINESYNC_IOC_WAIT_ALL``, it is not valid to pass the same
  object more than once. If this is attempted, the function fails with
  ``EINVAL``.

  Fails with ``ENOMEM`` if not enough memory is available, or
  ``EINTR`` if a signal is received.
