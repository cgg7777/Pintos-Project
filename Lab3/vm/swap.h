#ifndef __SWAP_H__
#define __SWAP_H__
void swap_partition_init(void);
void swap_in(size_t swap_idx, void *physical_address);
size_t swap_out(void *physical_address);
#endif
