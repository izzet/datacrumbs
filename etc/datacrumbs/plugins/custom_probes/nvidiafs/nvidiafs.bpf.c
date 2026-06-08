#include "nvidiafs.bpf.h"

#include <datacrumbs/server/bpf/common.h>

#define NVFS_EVENT_ID_START 400000

/* point event at an nvidia-fs op step (entry context = submitting process thread; TGID-filtered). */
#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1) && defined(DATACRUMBS_MODE) && \
    (DATACRUMBS_MODE == 1)
static inline __attribute__((always_inline)) int nvfs_point(struct pt_regs* ctx, u64 event_id) {
  u64 ts = bpf_ktime_get_ns();
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;  // only the traced process's contexts
  struct nvidiafs_event_t* event;
  DATACRUMBS_RB_RESERVE(output, struct nvidiafs_event_t, event);
  event->type = 6;  // -> get_data_6
  event->id = key.id;
  event->event_id = event_id;
  event->ts = ts;
  event->dur = 0;
  DATACRUMBS_EVENT_SUBMIT(event, key.id, event_id);
  return 0;
}
#else
static inline __attribute__((always_inline)) int nvfs_point(struct pt_regs* ctx, u64 event_id) {
  return 0;
}
#endif

/* per-op nvidia-fs driver entry: 1 per cuFileRead -> the cuFile<->nvidia-fs bridge */
SEC("kprobe/nvfs_io_start_op")
int BPF_KPROBE(nvfs_io_start_op_k) { return nvfs_point(ctx, NVFS_EVENT_ID_START + 0); }

/* TRUE zero-copy P2P DMA mapping taken (real GDS) */
SEC("kprobe/nvfs_get_p2p_dma_mapping")
int BPF_KPROBE(nvfs_p2p_k) { return nvfs_point(ctx, NVFS_EVENT_ID_START + 1); }

/* data staged through a host shadow/bounce buffer (NOT zero-copy) */
SEC("kprobe/nvfs_mgroup_pin_shadow_pages")
int BPF_KPROBE(nvfs_shadow_k) { return nvfs_point(ctx, NVFS_EVENT_ID_START + 2); }
