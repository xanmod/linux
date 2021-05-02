=====================
Multigenerational LRU
=====================

Quick Start
===========
Build Options
-------------
:Required: Set ``CONFIG_LRU_GEN=y``.

:Optional: Change ``CONFIG_NR_LRU_GENS`` to a number ``X`` to support
 a maximum of ``X`` generations.

:Optional: Change ``CONFIG_TIERS_PER_GEN`` to a number ``Y`` to support
 a maximum of ``Y`` tiers per generation.

:Optional: Set ``CONFIG_LRU_GEN_ENABLED=y`` to turn the feature on by
 default.

Runtime Options
---------------
:Required: Write ``1`` to ``/sys/kernel/mm/lru_gen/enable`` if the
 feature was not turned on by default.

:Optional: Change ``/sys/kernel/mm/lru_gen/spread`` to a number ``N``
 to spread pages out across ``N+1`` generations. ``N`` should be less
 than ``X``. Larger values make the background aging more aggressive.

:Optional: Read ``/sys/kernel/debug/lru_gen`` to verify the feature.
 This file has the following output:

::

  memcg  memcg_id  memcg_path
    node  node_id
      min_gen  birth_time  anon_size  file_size
      ...
      max_gen  birth_time  anon_size  file_size

Given a memcg and a node, ``min_gen`` is the oldest generation
(number) and ``max_gen`` is the youngest. Birth time is in
milliseconds. The sizes of anon and file types are in pages.

Recipes
-------
:Android on ARMv8.1+: ``X=4``, ``N=0``

:Android on pre-ARMv8.1 CPUs: Not recommended due to the lack of
 ``ARM64_HW_AFDBM``

:Laptops running Chrome on x86_64: ``X=7``, ``N=2``

:Working set estimation: Write ``+ memcg_id node_id gen [swappiness]``
 to ``/sys/kernel/debug/lru_gen`` to account referenced pages to
 generation ``max_gen`` and create the next generation ``max_gen+1``.
 ``gen`` should be equal to ``max_gen``. A swap file and a non-zero
 ``swappiness`` are required to scan anon type. If swapping is not
 desired, set ``vm.swappiness`` to ``0``.

:Proactive reclaim: Write ``- memcg_id node_id gen [swappiness]
 [nr_to_reclaim]`` to ``/sys/kernel/debug/lru_gen`` to evict
 generations less than or equal to ``gen``. ``gen`` should be less
 than ``max_gen-1`` as ``max_gen`` and ``max_gen-1`` are active
 generations and therefore protected from the eviction. Use
 ``nr_to_reclaim`` to limit the number of pages to be evicted.
 Multiple command lines are supported, so does concatenation with
 delimiters ``,`` and ``;``.

Framework
=========
For each ``lruvec``, evictable pages are divided into multiple
generations. The youngest generation number is stored in ``max_seq``
for both anon and file types as they are aged on an equal footing. The
oldest generation numbers are stored in ``min_seq[2]`` separately for
anon and file types as clean file pages can be evicted regardless of
swap and write-back constraints. Generation numbers are truncated into
``order_base_2(CONFIG_NR_LRU_GENS+1)`` bits in order to fit into
``page->flags``. The sliding window technique is used to prevent
truncated generation numbers from overlapping. Each truncated
generation number is an index to an array of per-type and per-zone
lists. Evictable pages are added to the per-zone lists indexed by
``max_seq`` or ``min_seq[2]`` (modulo ``CONFIG_NR_LRU_GENS``),
depending on whether they are being faulted in.

Each generation is then divided into multiple tiers. Tiers represent
levels of usage from file descriptors only. Pages accessed N times via
file descriptors belong to tier order_base_2(N). In contrast to moving
across generations which requires the lru lock, moving across tiers
only involves an atomic operation on ``page->flags`` and therefore has
a negligible cost.

The workflow comprises two conceptually independent functions: the
aging and the eviction.

Aging
-----
The aging produces young generations. Given an ``lruvec``, the aging
scans page tables for referenced pages of this ``lruvec``. Upon
finding one, the aging updates its generation number to ``max_seq``.
After each round of scan, the aging increments ``max_seq``.

The aging maintains either a system-wide ``mm_struct`` list or
per-memcg ``mm_struct`` lists, and it only scans page tables of
processes that have been scheduled since the last scan. Since scans
are differential with respect to referenced pages, the cost is roughly
proportional to their number.

The aging is due when both of ``min_seq[2]`` reaches ``max_seq-1``,
assuming both anon and file types are reclaimable.

Eviction
--------
The eviction consumes old generations. Given an ``lruvec``, the
eviction scans the pages on the per-zone lists indexed by either of
``min_seq[2]``. It first tries to select a type based on the values of
``min_seq[2]``. When anon and file types are both available from the
same generation, it selects the one that has a lower refault rate.

During a scan, the eviction sorts pages according to their generation
numbers, if the aging has found them referenced.  It also moves pages
from the tiers that have higher refault rates than tier 0 to the next
generation.

When it finds all the per-zone lists of a selected type are empty, the
eviction increments ``min_seq[2]`` indexed by this selected type.

Rationale
=========
Limitations of Current Implementation
-------------------------------------
Notion of Active/Inactive
~~~~~~~~~~~~~~~~~~~~~~~~~
For servers equipped with hundreds of gigabytes of memory, the
granularity of the active/inactive is too coarse to be useful for job
scheduling. False active/inactive rates are relatively high, and thus
the assumed savings may not materialize.

For phones and laptops, executable pages are frequently evicted
despite the fact that there are many less recently used anon pages.
Major faults on executable pages cause ``janks`` (slow UI renderings)
and negatively impact user experience.

For ``lruvec``\s from different memcgs or nodes, comparisons are
impossible due to the lack of a common frame of reference.

Incremental Scans via ``rmap``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Each incremental scan picks up at where the last scan left off and
stops after it has found a handful of unreferenced pages. For
workloads using a large amount of anon memory, incremental scans lose
the advantage under sustained memory pressure due to high ratios of
the number of scanned pages to the number of reclaimed pages. On top
of that, the ``rmap`` has poor memory locality due to its complex data
structures. The combined effects typically result in a high amount of
CPU usage in the reclaim path.

Benefits of Multigenerational LRU
---------------------------------
Notion of Generation Numbers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The notion of generation numbers introduces a quantitative approach to
memory overcommit. A larger number of pages can be spread out across
configurable generations, and thus they have relatively low false
active/inactive rates. Each generation includes all pages that have
been referenced since the last generation.

Given an ``lruvec``, scans and the selections between anon and file
types are all based on generation numbers, which are simple and yet
effective. For different ``lruvec``\s, comparisons are still possible
based on birth times of generations.

Differential Scans via Page Tables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Each differential scan discovers all pages that have been referenced
since the last scan. Specifically, it walks the ``mm_struct`` list
associated with an ``lruvec`` to scan page tables of processes that
have been scheduled since the last scan. The cost of each differential
scan is roughly proportional to the number of referenced pages it
discovers. Unless address spaces are extremely sparse, page tables
usually have better memory locality than the ``rmap``. The end result
is generally a significant reduction in CPU usage, for workloads
using a large amount of anon memory.

To-do List
==========
KVM Optimization
----------------
Support shadow page table scanning.

NUMA Optimization
-----------------
Support NUMA policies and per-node RSS counters.
