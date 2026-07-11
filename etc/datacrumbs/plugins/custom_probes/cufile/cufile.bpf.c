#include "cufile.bpf.h"

#include <datacrumbs/server/bpf/common.h>

/* cuFile plugin OWNS the GDS-Trace correlation maps; nvidiafs/block extern them. */
#define GDSTRACE_CORR_OWNER
#include "../gdstrace_corr.bpf.h"

/* carry entry args (size/offset/count) to the matching uretprobe, keyed per (tid,event_id) */
DATACRUMBS_MAP(cufile_args_map, struct fn_key_t, struct cufile_args_t);

#define CUFILE_EVENT_ID_START 200000
#define CUFILE_LIB "/usr/local/cuda-12.6/targets/x86_64-linux/lib/libcufile.so"

/* CUfileIOParams_t layout (cufile.h): stride 64 B; file_offset @ +16, size @ +32 (union.batch). */
#define CUFILE_IOPARAMS_STRIDE 64
#define CUFILE_IOPARAMS_OFF_FILEOFFSET 16
#define CUFILE_IOPARAMS_OFF_SIZE 32
#define CUFILE_BATCH_MAX 256  /* loop cap for the verifier */

/* ---- entry: stamp start time; optionally stash signature-derived size/offset/count ---- */
#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1)
static inline __attribute__((always_inline)) int cufile_entry(struct pt_regs* ctx, u64 event_id,
                                                              u64 size, u64 offset, u64 count,
                                                              int has_args) {
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;  // not tracing this process
  struct fn_value_t fn = {};
  fn.ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&fn_pid_map, &key, &fn, BPF_ANY);
  /* register this op's corr_id (= entry ts) so device ops (nvfs_io/NVMe) attribute to it by id,
   * whether they fire on this thread (synchronous) or on cuFile's worker threads (fastsafetensors). */
  gdstrace_corr_begin(fn.ts);
  if (has_args) {
    struct cufile_args_t a = {};
    a.size = size;
    a.offset = offset;
    a.count = count;
    bpf_map_update_elem(&cufile_args_map, &key, &a, BPF_ANY);
  }
  return 0;
}
#else
static inline __attribute__((always_inline)) int cufile_entry(struct pt_regs* ctx, u64 event_id,
                                                              u64 size, u64 offset, u64 count,
                                                              int has_args) {
  return 0;
}
#endif

/* ---- exit: emit cufile_event_t (type=4) with duration (+ size/offset/count if captured) ---- */
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
  u64 corr = fn->ts;     // this op's correlation id (= entry ts)
  gdstrace_corr_end();   // op done: stop attributing device ops to it
  DATACRUMBS_SKIP_SMALL_EVENTS(fn, te);
  struct cufile_event_t* event;
  DATACRUMBS_RB_RESERVE(output, struct cufile_event_t, event);
  event->type = 4;  // -> get_data_4 (1=general,2=sys_io,3=usdt already used)
  event->id = key.id;
  event->event_id = event_id;
  DATACRUMBS_COLLECT_TIME(event);
  event->corr_id = corr;
  event->size = 0;
  event->offset = 0;
  event->count = 0;
  struct cufile_args_t* a = bpf_map_lookup_elem(&cufile_args_map, &key);
  if (a != 0) {
    event->size = a->size;
    event->offset = a->offset;
    event->count = a->count;
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
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 0, size, file_offset, 0, 1);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileRead")
int BPF_URETPROBE(cuFileRead_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 0); }

SEC("uprobe/" CUFILE_LIB ":cuFileWrite")
int BPF_UPROBE(cuFileWrite_entry, void* fh, void* buf, u64 size, u64 file_offset) {
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 1, size, file_offset, 0, 1);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileWrite")
int BPF_URETPROBE(cuFileWrite_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 1); }

/* cuFileReadAsync(fh, buf, size_t* size_p, off_t* file_offset_p, ...): size/offset are POINTERS. */
SEC("uprobe/" CUFILE_LIB ":cuFileReadAsync")
int BPF_UPROBE(cuFileReadAsync_entry, void* fh, void* buf, u64* size_p, u64* file_offset_p) {
  u64 size = 0, off = 0;
  if (size_p) bpf_probe_read_user(&size, sizeof(size), size_p);
  if (file_offset_p) bpf_probe_read_user(&off, sizeof(off), file_offset_p);
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 2, size, off, 0, 1);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileReadAsync")
int BPF_URETPROBE(cuFileReadAsync_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 2); }

/* cuFileBatchIOSubmit(batch, nr, CUfileIOParams_t* iocbp, flags): walk the array, sum per-op sizes,
 * record nr as count and the total requested bytes as size. */
SEC("uprobe/" CUFILE_LIB ":cuFileBatchIOSubmit")
int BPF_UPROBE(cuFileBatchIOSubmit_entry, void* batch, unsigned int nr, void* iocbp,
               unsigned int flags) {
  u64 total = 0, off0 = 0;
  unsigned int n = nr;
  if (n > CUFILE_BATCH_MAX) n = CUFILE_BATCH_MAX;
  for (unsigned int i = 0; i < n; i++) {
    u64 sz = 0;
    char* p = (char*)iocbp + (u64)i * CUFILE_IOPARAMS_STRIDE;
    bpf_probe_read_user(&sz, sizeof(sz), p + CUFILE_IOPARAMS_OFF_SIZE);
    total += sz;
    if (i == 0) bpf_probe_read_user(&off0, sizeof(off0), p + CUFILE_IOPARAMS_OFF_FILEOFFSET);
  }
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 3, total, off0, nr, 1);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileBatchIOSubmit")
int BPF_URETPROBE(cuFileBatchIOSubmit_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 3); }

SEC("uprobe/" CUFILE_LIB ":cuFileHandleRegister")
int BPF_UPROBE(cuFileHandleRegister_entry) {
  return cufile_entry(ctx, CUFILE_EVENT_ID_START + 4, 0, 0, 0, 0);
}
SEC("uretprobe/" CUFILE_LIB ":cuFileHandleRegister")
int BPF_URETPROBE(cuFileHandleRegister_exit) { return cufile_exit(ctx, CUFILE_EVENT_ID_START + 4); }

/* ===== POSIX pread offset capture (for the silent kvikio POSIX-bypass class) =====
 * These reads never enter cuFile, so they must NOT register a corr_id (that is the whole point: the
 * time basis cannot see them). We only capture size+offset so the ADDRESS basis can attribute each
 * bypassed device command to the exact pread that issued it. libc pread64==pread==__pread64 (aliases). */
#define LIBC_PATH "/usr/lib/x86_64-linux-gnu/libc.so.6"
#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1)
static inline __attribute__((always_inline)) int pread_entry(struct pt_regs* ctx, u64 event_id,
                                                             u64 count, u64 offset) {
  struct fn_key_t key = {};
  key.event_id = event_id;
  u64 start_ts;
  if (!need_tracing(&key, &start_ts)) return 0;  // not tracing this process
  struct fn_value_t fn = {};
  fn.ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&fn_pid_map, &key, &fn, BPF_ANY);
  struct cufile_args_t a = {};
  a.size = count; a.offset = offset; a.count = 0;   // NB: no gdstrace_corr_begin -> POSIX carries no corr_id
  bpf_map_update_elem(&cufile_args_map, &key, &a, BPF_ANY);
  return 0;
}
#else
static inline __attribute__((always_inline)) int pread_entry(struct pt_regs* ctx, u64 event_id,
                                                             u64 count, u64 offset) { return 0; }
#endif

#if defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1) && defined(DATACRUMBS_MODE) && \
    (DATACRUMBS_MODE == 1)
static inline __attribute__((always_inline)) int pread_exit(struct pt_regs* ctx, u64 event_id) {
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
  event->type = 4;
  event->id = key.id;
  event->event_id = event_id;
  DATACRUMBS_COLLECT_TIME(event);
  event->corr_id = 0;  // POSIX: no cuFile correlation id
  event->size = 0; event->offset = 0; event->count = 0;
  struct cufile_args_t* a = bpf_map_lookup_elem(&cufile_args_map, &key);
  if (a != 0) {
    event->size = a->size; event->offset = a->offset;
    bpf_map_delete_elem(&cufile_args_map, &key);
  }
  DATACRUMBS_EVENT_SUBMIT(event, key.id, event_id);
  return 0;
}
#else
static inline __attribute__((always_inline)) int pread_exit(struct pt_regs* ctx, u64 event_id) { return 0; }
#endif

/* pread(fd, buf, count, offset): count=arg3, offset=arg4. */
SEC("uprobe/" LIBC_PATH ":pread")
int BPF_UPROBE(pread_gds_entry, int fd, void* buf, u64 count, u64 offset) {
  return pread_entry(ctx, CUFILE_EVENT_ID_START + 5, count, offset);
}
SEC("uretprobe/" LIBC_PATH ":pread")
int BPF_URETPROBE(pread_gds_exit) { return pread_exit(ctx, CUFILE_EVENT_ID_START + 5); }
