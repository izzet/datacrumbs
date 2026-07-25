#include "block.bpf.h"

#include <datacrumbs/server/bpf/common.h>

#include "../gdstrace_corr.bpf.h"  // cross-layer correlation (maps owned by the cuFile plugin)

#define BLOCK_EVENT_ID_START 300000

/* Point event at NVMe command setup. Entry-only (dur=0): records the device-command size+sector for
 * the traced process's threads (need_tracing filters by TGID). nvme_setup_cmd runs in the submitting
 * process context for GDS reads (verified), so worker-thread GDS commands are captured. */
#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1) && defined(DATACRUMBS_MODE) && \
    (DATACRUMBS_MODE == 1)
static inline __attribute__((always_inline)) int block_point(struct pt_regs* ctx, u64 event_id,
                                                             u64 size, u64 sector, u64 op) {
  u64 ts = bpf_ktime_get_ns();
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;  // only the traced process's contexts
  struct block_event_t* event;
  DATACRUMBS_RB_RESERVE(output, struct block_event_t, event);
  event->type = 5;  // -> get_data_5
  event->id = key.id;
  event->event_id = event_id;
  event->ts = ts;
  event->dur = 0;
  event->size = size;
  event->sector = sector;
  event->op = op;  // read vs write: RMW under a write workload shows up as REQ_OP_READ commands
  u32 sync = 0;
  event->corr_id = gdstrace_corr_current(&sync);  // the cuFileRead this NVMe cmd belongs to (0 if none)
  event->sync = sync;                             // 1 = same-thread valid owner; 0 = fallback/none
  DATACRUMBS_EVENT_SUBMIT(event, key.id, event_id);
  return 0;
}
#else
static inline __attribute__((always_inline)) int block_point(struct pt_regs* ctx, u64 event_id,
                                                             u64 size, u64 sector, u64 op) {
  return 0;
}
#endif

/* req->cmd_flags low bits hold the operation (REQ_OP_READ=0, REQ_OP_WRITE=1); REQ_OP_BITS is 8.
 * Defined locally because vmlinux BTF carries the field, not the kernel's REQ_OP_* macros. */
#define GDS_REQ_OP_MASK ((u64)((1 << 8) - 1))

/* nvme_setup_cmd(struct nvme_ns *ns, struct request *req) -- one NVMe command being issued.
 * size = req->__data_len (bytes), sector = req->__sector, op = direction. request is in vmlinux BTF. */
SEC("kprobe/nvme_setup_cmd")
int BPF_KPROBE(nvme_setup_cmd_entry, void* ns, struct request* req) {
  u64 size = BPF_CORE_READ(req, __data_len);
  u64 sector = BPF_CORE_READ(req, __sector);
  u32 cf = 0;
  bpf_core_read(&cf, sizeof(cf), &req->cmd_flags);
  u64 op = (u64)cf & GDS_REQ_OP_MASK;
  return block_point(ctx, BLOCK_EVENT_ID_START + 0, size, sector, op);
}
