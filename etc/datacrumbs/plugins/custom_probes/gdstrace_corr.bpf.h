#ifndef DATACRUMBS_CUSTOM_PROBES_GDSTRACE_CORR_BPF_H
#define DATACRUMBS_CUSTOM_PROBES_GDSTRACE_CORR_BPF_H

/* GDS-Trace cross-layer correlation (lives entirely in our plugins; no DataCrumbs core changes).
 *
 * Each cuFile op gets a corr_id (= its entry ktime). Device-layer events (nvfs_io, NVMe) stamp the
 * corr_id of the cuFileRead they belong to, so DFAnalyzer attributes by id rather than fragile
 * time-containment (which breaks when cuFile pipelines async ops or uses worker threads). Two paths:
 *   - same thread  (synchronous cuFile: gdsio/kvikio): cufile_active_op[tid]            -> exact.
 *   - worker thread (cuFile's internal pool: fastsafetensors): fall back to cufile_active_xor[tgid], the
 *     XOR of all active corr_ids, used ONLY when exactly one cuFile op is active (cufile_op_count[tgid]==1),
 *     where the XOR equals that sole op's id -- sound even when other ops entered and exited meanwhile
 *     (a plain last-writer proc[tgid] is not: count==1 does not imply it holds the surviving op). Under
 *     concurrency we return 0 (the same-thread path already attributes those correctly).
 *
 * The cuFile plugin defines the maps (include with GDSTRACE_CORR_OWNER); nvidiafs/block include for
 * externs. All plugin objects are statically linked into one datacrumbs.bpf.o, so the externs resolve.
 * Requires common.h included first (u32/u64 types + the DATACRUMBS_MAP macros + bpf helpers). */

#ifdef GDSTRACE_CORR_OWNER
DATACRUMBS_MAP(cufile_active_op, u32, u64, 10240);  // tid  -> active cuFile op corr_id (same-thread)
DATACRUMBS_MAP(cufile_op_count, u32, u64, 10240);   // tgid -> # of cuFile ops currently active
DATACRUMBS_MAP(cufile_active_xor, u32, u64, 10240); // tgid -> XOR of active corr_ids (== sole id when count==1)
#else
DATACRUMBS_MAP_EXTERN(cufile_active_op, u32, u64, 10240);
DATACRUMBS_MAP_EXTERN(cufile_op_count, u32, u64, 10240);
DATACRUMBS_MAP_EXTERN(cufile_active_xor, u32, u64, 10240);
#endif

/* cuFile op entry: register corr_id for this thread and bump the per-process active count. */
static inline __attribute__((always_inline)) void gdstrace_corr_begin(u64 corr_id) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt, tgid = (u32)(pt >> 32);
  bpf_map_update_elem(&cufile_active_op, &tid, &corr_id, BPF_ANY);
  u64* c = bpf_map_lookup_elem(&cufile_op_count, &tgid);
  u64 n = (c ? *c : 0) + 1;
  bpf_map_update_elem(&cufile_op_count, &tgid, &n, BPF_ANY);
  u64* x = bpf_map_lookup_elem(&cufile_active_xor, &tgid);
  u64 xv = (x ? *x : 0) ^ corr_id;
  bpf_map_update_elem(&cufile_active_xor, &tgid, &xv, BPF_ANY);
}

/* cuFile op exit: deregister, and XOR this op's id back out so cufile_active_xor holds only still-active ids. */
static inline __attribute__((always_inline)) void gdstrace_corr_end(void) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt, tgid = (u32)(pt >> 32);
  u64* mine = bpf_map_lookup_elem(&cufile_active_op, &tid);
  if (mine) {
    u64* x = bpf_map_lookup_elem(&cufile_active_xor, &tgid);
    if (x) { u64 xv = *x ^ *mine; bpf_map_update_elem(&cufile_active_xor, &tgid, &xv, BPF_ANY); }
  }
  bpf_map_delete_elem(&cufile_active_op, &tid);
  u64* c = bpf_map_lookup_elem(&cufile_op_count, &tgid);
  if (c && *c > 0) {
    u64 n = *c - 1;
    bpf_map_update_elem(&cufile_op_count, &tgid, &n, BPF_ANY);
    if (n == 0) bpf_map_delete_elem(&cufile_active_xor, &tgid);
  }
}

/* device-layer: corr_id of the cuFile op this op belongs to (0 if none / ambiguous). */
static inline __attribute__((always_inline)) u64 gdstrace_corr_current(void) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt, tgid = (u32)(pt >> 32);
  u64* c = bpf_map_lookup_elem(&cufile_active_op, &tid);
  if (c) return *c;  // same-thread (synchronous cuFile)
  u64* cnt = bpf_map_lookup_elem(&cufile_op_count, &tgid);
  if (cnt && *cnt == 1) {  // worker thread + exactly one active op -> XOR is that op's id (sound under overlap)
    u64* xp = bpf_map_lookup_elem(&cufile_active_xor, &tgid);
    if (xp) return *xp;
  }
  return 0;
}

#endif  // DATACRUMBS_CUSTOM_PROBES_GDSTRACE_CORR_BPF_H
