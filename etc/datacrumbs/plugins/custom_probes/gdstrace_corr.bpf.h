#ifndef DATACRUMBS_CUSTOM_PROBES_GDSTRACE_CORR_BPF_H
#define DATACRUMBS_CUSTOM_PROBES_GDSTRACE_CORR_BPF_H

/* GDS-Trace cross-layer correlation (lives entirely in our plugins; no DataCrumbs core changes).
 *
 * Each cuFile op gets a corr_id (= its entry ktime). Device-layer events (nvfs_io, NVMe) stamp the
 * corr_id of the cuFileRead they belong to, so DFAnalyzer attributes by id rather than fragile
 * time-containment (which breaks when cuFile pipelines async ops or uses worker threads). Two paths:
 *   - same thread  (synchronous cuFile: gdsio/kvikio): cufile_active_op[tid]            -> exact.
 *   - worker thread (cuFile's internal pool: fastsafetensors): process-level fallback, used ONLY when
 *     exactly one cuFile op is active in the process (cufile_op_count[tgid]==1) -> unambiguous; under
 *     concurrency we return 0 (the same-thread path already attributes those correctly).
 *
 * The cuFile plugin defines the maps (include with GDSTRACE_CORR_OWNER); nvidiafs/block include for
 * externs. All plugin objects are statically linked into one datacrumbs.bpf.o, so the externs resolve.
 * Requires common.h included first (u32/u64 types + the DATACRUMBS_MAP macros + bpf helpers). */

#ifdef GDSTRACE_CORR_OWNER
DATACRUMBS_MAP(cufile_active_op, u32, u64, 10240);  // tid  -> active cuFile op corr_id (same-thread)
DATACRUMBS_MAP(cufile_op_count, u32, u64, 10240);   // tgid -> # of cuFile ops currently active
DATACRUMBS_MAP(cufile_proc_op, u32, u64, 10240);    // tgid -> the corr_id (usable when count==1)
#else
DATACRUMBS_MAP_EXTERN(cufile_active_op, u32, u64, 10240);
DATACRUMBS_MAP_EXTERN(cufile_op_count, u32, u64, 10240);
DATACRUMBS_MAP_EXTERN(cufile_proc_op, u32, u64, 10240);
#endif

/* cuFile op entry: register corr_id for this thread and bump the per-process active count. */
static inline __attribute__((always_inline)) void gdstrace_corr_begin(u64 corr_id) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt, tgid = (u32)(pt >> 32);
  bpf_map_update_elem(&cufile_active_op, &tid, &corr_id, BPF_ANY);
  u64* c = bpf_map_lookup_elem(&cufile_op_count, &tgid);
  u64 n = (c ? *c : 0) + 1;
  bpf_map_update_elem(&cufile_op_count, &tgid, &n, BPF_ANY);
  bpf_map_update_elem(&cufile_proc_op, &tgid, &corr_id, BPF_ANY);
}

/* cuFile op exit: deregister; clear the process op when none remain. */
static inline __attribute__((always_inline)) void gdstrace_corr_end(void) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt, tgid = (u32)(pt >> 32);
  bpf_map_delete_elem(&cufile_active_op, &tid);
  u64* c = bpf_map_lookup_elem(&cufile_op_count, &tgid);
  if (c && *c > 0) {
    u64 n = *c - 1;
    bpf_map_update_elem(&cufile_op_count, &tgid, &n, BPF_ANY);
    if (n == 0) bpf_map_delete_elem(&cufile_proc_op, &tgid);
  }
}

/* device-layer: corr_id of the cuFile op this op belongs to (0 if none / ambiguous). */
static inline __attribute__((always_inline)) u64 gdstrace_corr_current(void) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt, tgid = (u32)(pt >> 32);
  u64* c = bpf_map_lookup_elem(&cufile_active_op, &tid);
  if (c) return *c;  // same-thread (synchronous cuFile)
  u64* cnt = bpf_map_lookup_elem(&cufile_op_count, &tgid);
  if (cnt && *cnt == 1) {  // cuFile worker thread + exactly one active op -> unambiguous
    u64* pc = bpf_map_lookup_elem(&cufile_proc_op, &tgid);
    if (pc) return *pc;
  }
  return 0;
}

#endif  // DATACRUMBS_CUSTOM_PROBES_GDSTRACE_CORR_BPF_H
