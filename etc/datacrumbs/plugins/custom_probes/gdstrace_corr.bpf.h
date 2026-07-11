#ifndef DATACRUMBS_CUSTOM_PROBES_GDSTRACE_CORR_BPF_H
#define DATACRUMBS_CUSTOM_PROBES_GDSTRACE_CORR_BPF_H

/* GDS-Trace cross-layer correlation (lives entirely in our plugins; no DataCrumbs core changes).
 *
 * Each cuFile op gets a corr_id (= its entry ktime). Device-layer events (nvfs_io, NVMe) stamp the
 * corr_id of the cuFileRead they belong to, so DFAnalyzer attributes by id rather than fragile
 * time-containment (which breaks when cuFile pipelines async ops or uses worker threads). Two paths:
 *   - same thread  (synchronous cuFile: gdsio/kvikio): cufile_active_op[tid]            -> exact.
 *   - worker thread (cuFile's internal pool: fastsafetensors): fall back to cufile_proc[tgid].xorv, the
 *     XOR of all active corr_ids, used ONLY when exactly one op is active (cufile_proc[tgid].cnt==1),
 *     where the XOR equals that sole op's id. cnt and xorv are updated with ATOMIC ops (bpf_spin_lock is
 *     rejected in tracing programs), so concurrent entry/exit on different threads never lose an update.
 *     A torn read of the pair (new cnt, old xorv) is self-invalidating: xorv would be A^B, not any real
 *     corr_id, so it misses the cufile table and yields no attribution (address handles the command)
 *     rather than a wrong one. The per-thread active_op is single-writer and needs no atomics.
 *
 * The cuFile plugin defines the maps (include with GDSTRACE_CORR_OWNER); nvidiafs/block include for
 * externs. All plugin objects are statically linked into one datacrumbs.bpf.o, so the externs resolve.
 * Requires common.h included first (u32/u64 types + the DATACRUMBS_MAP macros + bpf helpers). */

struct cufile_proc_t {          /* per-process active-op accounting, updated with atomic ops */
  u64 cnt;                       /* # of cuFile ops currently active in this tgid */
  u64 xorv;                      /* XOR of their corr_ids (== the sole id when cnt==1) */
};

#ifdef GDSTRACE_CORR_OWNER
DATACRUMBS_MAP(cufile_active_op, u32, u64, 10240);             // tid  -> active corr_id (per-thread, no lock)
DATACRUMBS_MAP(cufile_proc, u32, struct cufile_proc_t, 10240); // tgid -> {cnt,xorv} under a spin lock
#else
DATACRUMBS_MAP_EXTERN(cufile_active_op, u32, u64, 10240);
DATACRUMBS_MAP_EXTERN(cufile_proc, u32, struct cufile_proc_t, 10240);
#endif

/* cuFile op entry: register corr_id for this thread and atomically bump the per-process (cnt,xorv). */
static inline __attribute__((always_inline)) void gdstrace_corr_begin(u64 corr_id) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt, tgid = (u32)(pt >> 32);
  bpf_map_update_elem(&cufile_active_op, &tid, &corr_id, BPF_ANY);
  struct cufile_proc_t init = {};
  bpf_map_update_elem(&cufile_proc, &tgid, &init, BPF_NOEXIST);  // create once if absent
  struct cufile_proc_t* p = bpf_map_lookup_elem(&cufile_proc, &tgid);
  if (p) {
    __sync_fetch_and_add(&p->cnt, 1);
    __sync_fetch_and_xor(&p->xorv, corr_id);
  }
}

/* cuFile op exit: deregister; atomically XOR this op's id back out and decrement cnt. */
static inline __attribute__((always_inline)) void gdstrace_corr_end(void) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt, tgid = (u32)(pt >> 32);
  u64* mine = bpf_map_lookup_elem(&cufile_active_op, &tid);
  struct cufile_proc_t* p = bpf_map_lookup_elem(&cufile_proc, &tgid);
  if (p && mine) {
    __sync_fetch_and_xor(&p->xorv, *mine);
    __sync_fetch_and_add(&p->cnt, (u64)-1);
  }
  bpf_map_delete_elem(&cufile_active_op, &tid);
}

/* device-layer: corr_id of the cuFile op this op belongs to (0 if none). *sync_out=1 iff the id came from
 * the same-thread active_op path -- a synchronous op holds its thread, so nothing foreign can fire on it
 * while active_op is set, making this a provably VALID owner. The off-thread process fallback sets
 * *sync_out=0 (best-effort; the offline composition never trusts it to break an address tie). */
static inline __attribute__((always_inline)) u64 gdstrace_corr_current(u32* sync_out) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt, tgid = (u32)(pt >> 32);
  if (sync_out) *sync_out = 0;
  u64* c = bpf_map_lookup_elem(&cufile_active_op, &tid);
  if (c) { if (sync_out) *sync_out = 1; return *c; }  // same-thread -> VALID owner
  struct cufile_proc_t* p = bpf_map_lookup_elem(&cufile_proc, &tgid);
  if (p) {
    u64 cnt = p->cnt, xorv = p->xorv;
    if (cnt == 1) return xorv;          // off-thread fallback -> sync_out stays 0 (untrusted)
  }
  return 0;
}

#endif  // DATACRUMBS_CUSTOM_PROBES_GDSTRACE_CORR_BPF_H
