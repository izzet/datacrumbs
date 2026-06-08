#ifndef DATACRUMBS_CUSTOM_PROBES_CUFILE_CUFILE_BPF_H
#define DATACRUMBS_CUSTOM_PROBES_CUFILE_CUFILE_BPF_H

#include <datacrumbs/server/bpf/shared.h>

/* Per-op cuFile/GDS event: like general_event_t plus signature-derived size+offset. */
struct cufile_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
  unsigned long long size;
  unsigned long long offset;
};

/* args captured at uprobe entry, carried to uretprobe exit (keyed by fn_key_t). */
struct cufile_args_t {
  unsigned long long size;
  unsigned long long offset;
};

#endif  // DATACRUMBS_CUSTOM_PROBES_CUFILE_CUFILE_BPF_H
