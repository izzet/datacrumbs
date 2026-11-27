#ifndef DATACRUMBS_CUSTOM_PROBES_NVIDIAFS_NVIDIAFS_BPF_H
#define DATACRUMBS_CUSTOM_PROBES_NVIDIAFS_NVIDIAFS_BPF_H

#include <datacrumbs/server/bpf/shared.h>

/* nvidia-fs (the middle GDS layer) POINT event. The function (via event_id) is the signal:
 *   nvfs_io                   - per-op driver entry (nvfs_io_start_op) = the cuFile<->nvidia-fs bridge
 *   nvfs_get_p2p_dma_mapping  - TRUE zero-copy P2P DMA path taken
 *   nvfs_mgroup_pin_shadow_pages - data STAGED through a host shadow/bounce buffer (not zero-copy)
 * Each carries corr_id = the active cuFileRead's id on this thread, so device ops attribute to the
 * originating cuFileRead by id (robust to async overlap) rather than fragile time-containment.
 */
struct nvidiafs_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
  unsigned long long corr_id;
};

#endif  // DATACRUMBS_CUSTOM_PROBES_NVIDIAFS_NVIDIAFS_BPF_H
