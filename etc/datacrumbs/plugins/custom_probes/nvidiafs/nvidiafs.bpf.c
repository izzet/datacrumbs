#include "nvidiafs.bpf.h"

#include <datacrumbs/server/bpf/common.h>

#define NVFS_EVENT_ID_START 400000

/* nvfs_io is a DURATION op: nvfs_io_start_op (entry) -> nvfs_io_complete (exit), both on the
 * submitting thread (verified) -> nvidia-fs op latency nested under the cuFileRead.
 * p2p / shadow are point markers (true-P2P vs host-bounce signal). */

#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1)
/* entry: stamp start time for the nvfs_io op */
static inline __attribute__((always_inline)) int nvfs_entry(struct pt_regs* ctx, u64 event_id) {
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;
  struct fn_value_t fn = {};
  fn.ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&fn_pid_map, &key, &fn, BPF_ANY);
  return 0;
}
#else
static inline __attribute__((always_inline)) int nvfs_entry(struct pt_regs* ctx, u64 event_id) {
  return 0;
}
#endif

#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1) && defined(DATACRUMBS_MODE) && \
    (DATACRUMBS_MODE == 1)
/* exit: emit the nvfs_io duration event (nested under cuFileRead) */
static inline __attribute__((always_inline)) int nvfs_exit(struct pt_regs* ctx, u64 event_id) {
  u64 te = bpf_ktime_get_ns();
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;
  struct fn_value_t* fn = bpf_map_lookup_elem(&fn_pid_map, &key);
  if (fn == 0) return 0;  // missed entry
  DATACRUMBS_SKIP_SMALL_EVENTS(fn, te);  // drop sub-threshold noise (same filter as cuFile layer)
  struct nvidiafs_event_t* event;
  DATACRUMBS_RB_RESERVE(output, struct nvidiafs_event_t, event);
  event->type = 6;
  event->id = key.id;
  event->event_id = event_id;
  DATACRUMBS_COLLECT_TIME(event);
  DATACRUMBS_EVENT_SUBMIT(event, key.id, event_id);
  return 0;
}
/* point: a marker (P2P or shadow path taken), dur=0 */
static inline __attribute__((always_inline)) int nvfs_point(struct pt_regs* ctx, u64 event_id) {
  u64 ts = bpf_ktime_get_ns();
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;
  struct nvidiafs_event_t* event;
  DATACRUMBS_RB_RESERVE(output, struct nvidiafs_event_t, event);
  event->type = 6;
  event->id = key.id;
  event->event_id = event_id;
  event->ts = ts;
  event->dur = 0;
  DATACRUMBS_EVENT_SUBMIT(event, key.id, event_id);
  return 0;
}
#else
static inline __attribute__((always_inline)) int nvfs_exit(struct pt_regs* ctx, u64 event_id) {
  return 0;
}
static inline __attribute__((always_inline)) int nvfs_point(struct pt_regs* ctx, u64 event_id) {
  return 0;
}
#endif

/* nvfs_io DURATION: start_op -> complete (same thread) = nvidia-fs op latency */
SEC("kprobe/nvfs_io_start_op")
int BPF_KPROBE(nvfs_io_start_op_k) { return nvfs_entry(ctx, NVFS_EVENT_ID_START + 0); }
SEC("kprobe/nvfs_io_complete")
int BPF_KPROBE(nvfs_io_complete_k) { return nvfs_exit(ctx, NVFS_EVENT_ID_START + 0); }

/* TRUE zero-copy P2P DMA mapping taken (real GDS) */
SEC("kprobe/nvfs_get_p2p_dma_mapping")
int BPF_KPROBE(nvfs_p2p_k) { return nvfs_point(ctx, NVFS_EVENT_ID_START + 1); }

/* data staged through a host shadow/bounce buffer (NOT zero-copy) */
SEC("kprobe/nvfs_mgroup_pin_shadow_pages")
int BPF_KPROBE(nvfs_shadow_k) { return nvfs_point(ctx, NVFS_EVENT_ID_START + 2); }
