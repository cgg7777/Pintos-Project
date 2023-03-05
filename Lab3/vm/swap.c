#include <stdio.h>
#include <bitmap.h>
#include "devices/block.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "vm/file.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"

//bitmap is swap partition's bitmap
struct bitmap *swap_bitmap;
struct block *swap_block;
struct lock bitmap_lock;


void swap_partition_init(void){
  lock_init(&(bitmap_lock));
  swap_block = block_get_role(BLOCK_SWAP);
  if(swap_block == NULL){
    return;
  }
  // page per block. just one bit need per one page.
  // swap partition is page unit. so bit number is page per block
  // sector/block / sector/page -> page/block
  swap_bitmap = bitmap_create(block_size(swap_block) * PGSIZE / BLOCK_SECTOR_SIZE);
  if(swap_bitmap == NULL){
    return;
  }
  bitmap_set_all(swap_bitmap, 0);
}

void swap_in(size_t swap_idx, void *physical_address){

  //if(bitmap_lock.holder != NULL)
  //  printf(" **** /page.c : swap_in - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, bitmap_lock.holder->tid);
    
    
  lock_acquire(&(bitmap_lock));
  if(bitmap_test(swap_bitmap, swap_idx) == 0){
    lock_release(&(bitmap_lock));
    return;
  }
  // must loop for 'sector per page'
  int i, sector_per_page = PGSIZE / BLOCK_SECTOR_SIZE;
  block_sector_t sector_number = sector_per_page * swap_idx;
  for(i = 0; i<sector_per_page; i++, sector_number++){
    block_read(swap_block, sector_number, physical_address);
    physical_address += BLOCK_SECTOR_SIZE;
  }
  //block_read(swap_block, ???, physical_address);
  // if use, then 1
  bitmap_set(swap_bitmap, swap_idx, 0);
  
  lock_release(&(bitmap_lock));
}

size_t swap_out(void *physical_address){


  //if(bitmap_lock.holder != NULL)
  //  printf(" **** /page.c : swap_out - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, bitmap_lock.holder->tid);
    
  lock_acquire(&(bitmap_lock));
  
  // find bitmap index and change, and write to file
  size_t zero_swap_idx = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);
  
  if(zero_swap_idx == BITMAP_ERROR){
    return BITMAP_ERROR;
  }
  int i, sector_per_page = PGSIZE / BLOCK_SECTOR_SIZE;
  block_sector_t sector_number = sector_per_page * zero_swap_idx;
  for(i = 0; i<sector_per_page; i++, sector_number++){
    block_write(swap_block, sector_number, physical_address);
    physical_address += BLOCK_SECTOR_SIZE;
  }
  
  lock_release(&(bitmap_lock));
  
  return zero_swap_idx;
}
