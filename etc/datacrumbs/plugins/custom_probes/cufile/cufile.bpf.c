#include "cufile.bpf.h"

#include <datacrumbs/server/bpf/common.h>

/* carry entry args (size/offset) to the matching uretprobe, keyed per (tid,event_id) */
DATACRUMBS_MAP(cufile_args_map, struct fn_key_t, struct cufile_args_t);

#define CUFILE_EVENT_ID_START 200000
#define CUFILE_LIB "/usr/local/cuda-12.6/targets/x86_64-linux/lib/libcufile.so"

/* ---- entry: stamp start time; optionally stash signature-derived size/offset ---- */
#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1)
static inline __attribute__((always_inline)) int cufile_entry(struct pt_regs* ctx, u64 event_id,
                                                              u64 size, u64 offset, int has_args) {
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;  // not tracing this process
  struct fn_value_t fn = {};
  fn.ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&fn_pid_map, &key, &fn, BPF_ANY);
  if (has_args) {
    struct cufile_args_t a = {};
    a.size = size;
    a.offset = offset;
    bpf_map_update_elem(&cufile_args_map, &key, &a, BPF_ANY);
  }
  return 0;
}
#else
static inline __attribute__((always_inline)) int cufile_entry(struct pt_regs* ctx, u64 event_id,
                                                              u64 size, u64 offset, int has_args) {
  return 0;
}
#endif

/* ---- exit: emit cufile_event_t (type=3) with duration (+ size/offset if captured) ---- */
#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1) && defined(DATACRUMBS_MODE) && \
    (DATACRUMBS_MODE == 1)
static inline __attribute__((always_inline)) int cufile_exit(struct pt_regs* ctx, u64 event_id) {
  u64 te = bpf_ktime_get_ns();
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;
  struct fn_value_t* fn = bpf_map_lookup_elem(&fn_pid_map, &key);
  if (fn == 0) return 0;  // missed entry
  DATACRUMBS_SKIP_SMALL_EVENTS(fn, te);
  struct cufile_event_t* event;
  DATACRUMBS_RB_RESERVE(output, struct cufile_event_t, event);
  event->type = 4;  // -> get_data_4 (1=general,2=sys_io,3=usdt already used)
  event->id = key.id;
  event->event_id = event_id;
  DATACRUMBS_COLLECT_TIME(event);
  event->size = 0;
  event->offset = 0;
  struct cufile_args_t* a = bpf_map_lookup_elem(&cufile_args_map, &key);
  if (a != 0) {
    event->size = a->size;
    event->offset = a->offset;
    bpf_map_delete_elem(&cufile_args_map, &key);
  }
  DATACRUMBS_EVENT_SUBMIT(event, key.id, event_id);
  return 0;
}
#else
static inline __attribute__((always_inline)) int cufile_exit(struct pt_regs* ctx, u64 event_id) {
  return 0;
}
#endif

/* ===== explicit, signature-aware SEC programs per cuFile function =====
 * cuFileRead/Write(fh, bufPtr_base, size, file_offset, bufPtr_offset): size=arg3, offset=arg4. */
SEC("uprobe/" CUFILE_LIB ":cuFileRead")
int BPF_UPROBE(cuFileRead_entry, void* fh, void* buf, u64 size, u64 file_offset) {
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 0, size, file_offset, 1);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileRead")
int BPF_URETPROBE(cuFileRead_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 0); }

SEC("uprobe/" CUFILE_LIB ":cuFileWrite")
int BPF_UPROBE(cuFileWrite_entry, void* fh, void* buf, u64 size, u64 file_offset) {
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 1, size, file_offset, 1);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileWrite")
int BPF_URETPROBE(cuFileWrite_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 1); }

/* cuFileReadAsync(fh, buf, size_t* size_p, off_t* file_offset_p, ...): size/offset are POINTERS. */
SEC("uprobe/" CUFILE_LIB ":cuFileReadAsync")
int BPF_UPROBE(cuFileReadAsync_entry, void* fh, void* buf, u64* size_p, u64* file_offset_p) {
  u64 size = 0, off = 0;
  if (size_p) bpf_probe_read_user(&size, sizeof(size), size_p);
  if (file_offset_p) bpf_probe_read_user(&off, sizeof(off), file_offset_p);
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 2, size, off, 1);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileReadAsync")
int BPF_URETPROBE(cuFileReadAsync_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 2); }

/* duration-only for now (batch params are an array; handle reg has no size). */
SEC("uprobe/" CUFILE_LIB ":cuFileBatchIOSubmit")
int BPF_UPROBE(cuFileBatchIOSubmit_entry) {
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 3, 0, 0, 0);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileBatchIOSubmit")
int BPF_URETPROBE(cuFileBatchIOSubmit_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 3); }

SEC("uprobe/" CUFILE_LIB ":cuFileHandleRegister")
int BPF_UPROBE(cuFileHandleRegister_entry) {
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 4, 0, 0, 0);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileHandleRegister")
int BPF_URETPROBE(cuFileHandleRegister_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 4); }
