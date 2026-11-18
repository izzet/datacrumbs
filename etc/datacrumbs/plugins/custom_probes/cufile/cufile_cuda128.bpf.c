/* cuFile plugin against the CUDA 12.8 libcufile (GDS 1.13, needed for the kernel PCI P2PDMA
 * transport). Same handlers as cufile.bpf.c; only the uprobe target library changes. The default
 * plugin stays on CUDA 12.6, the configuration the paper measured. */
#define CUFILE_LIB "/usr/local/cuda-12.8/targets/x86_64-linux/lib/libcufile.so"
#include "cufile.bpf.c"
