#include "p2pdma.bpf.h"

#include <datacrumbs/server/bpf/common.h>

#include "../gdstrace_corr.bpf.h"  // cross-layer correlation (maps owned by the cuFile plugin)

#define P2PDMA_EVENT_ID_START 500000

/* Kernel PCI P2PDMA POINT event, stamped with the active cuFileRead's corr_id on this thread. The
 * function (via event_id) is the signal; attribution is by corr_id, not duration. */
#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1) && defined(DATACRUMBS_MODE) && \
    (DATACRUMBS_MODE == 1)
static inline __attribute__((always_inline)) int p2pdma_point(struct pt_regs* ctx, u64 event_id) {
  u64 ts = bpf_ktime_get_ns();
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;  // only the traced process's contexts
  struct p2pdma_event_t* event;
  DATACRUMBS_RB_RESERVE(output, struct p2pdma_event_t, event);
  event->type = 7;  // -> get_data_7
  event->id = key.id;
  event->event_id = event_id;
  event->ts = ts;
  event->dur = 0;
  event->corr_id = gdstrace_corr_current(0);  // the cuFileRead this op belongs to (0 if none)
  DATACRUMBS_EVENT_SUBMIT(event, key.id, event_id);
  return 0;
}
#else
static inline __attribute__((always_inline)) int p2pdma_point(struct pt_regs* ctx, u64 event_id) {
  return 0;
}
#endif

/* TRUE P2P: one call per scatter-gather segment mapped to P2P (GPU BAR) memory. */
SEC("kprobe/pci_p2pdma_map_segment")
int BPF_KPROBE(pci_p2pdma_map_segment_k) { return p2pdma_point(ctx, P2PDMA_EVENT_ID_START + 0); }
