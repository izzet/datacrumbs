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

#include "cufile.bpf.h"

#define GET_DATA_4_EXISTS

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
datacrumbs::EventWithId* get_data_4(void* data, uint64_t index) {
  struct cufile_event_t* base = (struct cufile_event_t*)data;
  auto args = new DataCrumbsArgs();
  if (base->size != 0) {
    args->emplace("size", base->size);
    args->emplace("offset", base->offset);
  }
  auto event = new datacrumbs::EventWithId(NORMAL_EVENT, index, base->type, base->id,
                                           base->event_id, base->ts, base->dur, args);
  return event;
}
#else
/* profile (counter) mode for cuFile not implemented yet; TRACE mode is the supported path. */
datacrumbs::EventWithId* get_data_4(void* data, uint64_t index) { return nullptr; }
#endif
