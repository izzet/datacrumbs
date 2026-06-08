#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/typedefs.h>
#include <datacrumbs/server/process/event_processor.h>

#include <cstdint>
#include <string>

#include "nvidiafs.bpf.h"

#define GET_DATA_6_EXISTS

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
datacrumbs::EventWithId* get_data_6(void* data, uint64_t index) {
  struct nvidiafs_event_t* base = (struct nvidiafs_event_t*)data;
  auto args = new DataCrumbsArgs();
  if (base->corr_id != 0) {
    args->emplace("corr_id", base->corr_id);  // -> the cuFileRead this device op belongs to
  }
  auto event = new datacrumbs::EventWithId(NORMAL_EVENT, index, base->type, base->id,
                                           base->event_id, base->ts, base->dur, args);
  return event;
}
#else
datacrumbs::EventWithId* get_data_6(void* data, uint64_t index) { return nullptr; }
#endif
