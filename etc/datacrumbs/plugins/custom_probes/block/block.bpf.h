#ifndef DATACRUMBS_CUSTOM_PROBES_BLOCK_BLOCK_BPF_H
#define DATACRUMBS_CUSTOM_PROBES_BLOCK_BLOCK_BPF_H

#include <datacrumbs/server/bpf/shared.h>

/* NVMe device-command point event (one per nvme_setup_cmd): size + sector of the request.
 * Correlate against cuFileRead (same tid, within its [ts, ts+dur]) to get per-op amplification. */
struct block_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
  unsigned long long size;
  unsigned long long sector;
};

#endif  // DATACRUMBS_CUSTOM_PROBES_BLOCK_BLOCK_BPF_H
