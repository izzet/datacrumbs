#ifndef DATACRUMBS_CUSTOM_PROBES_P2PDMA_P2PDMA_BPF_H
#define DATACRUMBS_CUSTOM_PROBES_P2PDMA_P2PDMA_BPF_H

#include <datacrumbs/server/bpf/shared.h>

/* Kernel PCI P2PDMA (the upstream GDS transport, CUDA >= 12.8 with use_pci_p2pdma) POINT event.
 *   pci_p2pdma_map_segment - the DMA mapping layer maps one scatter-gather segment that targets
 *                            P2P (GPU BAR) memory, i.e. a TRUE device-to-GPU transfer.
 * It does not fire for host-staged (compat) reads. nvidia-fs is bypassed on this transport, so this
 * plugin replaces the nvidiafs P2P marker there and does not depend on the nvidia_fs module.
 * Each event carries corr_id = the active cuFileRead's id on this thread, as the nvidiafs events do.
 */
struct p2pdma_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
  unsigned long long corr_id;
};

#endif  // DATACRUMBS_CUSTOM_PROBES_P2PDMA_P2PDMA_BPF_H
