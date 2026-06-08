#ifndef DATACRUMBS_CUSTOM_PROBES_BLOCK_BLOCK_BPF_H
#define DATACRUMBS_CUSTOM_PROBES_BLOCK_BLOCK_BPF_H

#include <datacrumbs/server/bpf/shared.h>

/* NVMe device-command point event (one per nvme_setup_cmd): size + sector of the request.
 * corr_id = the active cuFileRead's id on this thread -> per-op amplification by id (not time-window). */
struct block_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
  unsigned long long size;
  unsigned long long sector;
  unsigned long long corr_id;
};

#endif  // DATACRUMBS_CUSTOM_PROBES_BLOCK_BLOCK_BPF_H
