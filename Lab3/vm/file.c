#include <stdio.h>
#include <stdbool.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/file.h"
#include "vm/page.h"
#include "vm/swap.h"

struct list clock_list;
struct lock clock_list_lock;
struct page *clock_current_page;



void clock_list_init(void){
  list_init(&(clock_list));
  lock_init(&(clock_list_lock));
  clock_current_page = NULL;
}

struct page *alloc_get_page(enum palloc_flags alloc_flag){
  if(alloc_flag & PAL_USER == 0){
    return NULL;
  }
  
  void *palloc_address = palloc_get_page(alloc_flag);
  while(palloc_address == NULL){
    evict_clock_page(alloc_flag);
    palloc_address = palloc_get_page(alloc_flag);  
  }
  //if(clock_list_lock.holder != NULL)
  //  printf(" **** /file.c : alloc_get_page - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, clock_list_lock.holder->tid);
  lock_acquire(&(clock_list_lock));
  struct page *palloc_page = malloc(sizeof(struct page));
  if(palloc_page == NULL){
    
    palloc_free_page(palloc_address);
    lock_release(&(clock_list_lock));
    
    return NULL;
  }
  palloc_page->physical_address = palloc_address;
  palloc_page->t = thread_current();
  list_push_back(&(clock_list), &(palloc_page->clock_elem));
  lock_release(&(clock_list_lock));
  
  return palloc_page;
}

void alloc_free_page(void *free_page_address){
  struct list_elem *iter;
  
  //if(clock_list_lock.holder != NULL)
  //  printf(" **** /file.c : alloc_free_page - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, clock_list_lock.holder->tid);
  lock_acquire(&(clock_list_lock));
  
  for(iter = list_begin(&(clock_list)); iter != list_end(&(clock_list));){
    struct page *cur_page = list_entry(iter, struct page, clock_elem);
    if(free_page_address == cur_page->physical_address){
      palloc_free_page(cur_page->physical_address);
      if(clock_current_page == cur_page){
        iter = list_remove(&(cur_page->clock_elem));
        clock_current_page = list_entry(iter, struct page, clock_elem);
      }
      else{
        iter = list_remove(&(cur_page->clock_elem));
      }
      free(cur_page);
      break;
    }
    else{
      iter = list_next(iter);
    }
  }
  
  lock_release(&(clock_list_lock));
}

static struct list_elem *next_clock_list_page(void){
  // if don't see any page, then need to allocate clock list's begin
  if(clock_current_page == NULL){
    // if clock list is empty, then nothing set
    if(list_begin(&(clock_list)) == list_end(&(clock_list))){
      return NULL;
    }
    // else clock list have any page, then allocate list begin.
    else{
      clock_current_page = list_entry(list_begin(&(clock_list)), struct page, clock_elem);
      return list_begin(&(clock_list));
    }
  }
  // if see some page, then need to see next clock page.
  else{
    // if next page is list end, then need to see first page
    if(list_next(&(clock_current_page->clock_elem)) == list_end(&(clock_list))){
      clock_current_page = list_entry(list_begin(&(clock_list)), struct page, clock_elem);
      return list_begin(&(clock_list));
    }
    // if next page is not list end, then need to see next page
    else{
      clock_current_page = list_entry(list_next(&(clock_current_page->clock_elem)), struct page, clock_elem);
      return list_next(&(clock_current_page->clock_elem));
    }
  }
}
/*
static struct list_elem *next_clock_list_page(void){
  if(list_empty(&(clock_list))){
    clock_current_page = NULL;
    return NULL;
  }
  else if(list_next(&(clock_current_page->clock_elem)) == list_end(&(clock_list))){
    list_elem *temp = list_begin(&(clock_list));
    clock_current_page = list_entry(temp, struct page, clock_elem);\
    return temp;
  }
  else{
    list_elem *temp = list_next(&(clock_current_page->clock_elem));
    clock_current_page = list_entry(temp, struct page, clock_elem);
    return temp;
  }
}
*/

void evict_clock_page(enum palloc_flags flags){
  struct page *victim_page;
 
 
  if(list_empty(&(clock_list)) == true){
    return;
  }
 
 
  while(1){
    next_clock_list_page();
    if(clock_current_page == NULL){
      return;
    }
    if(pagedir_is_accessed(clock_current_page->t->pagedir, clock_current_page->vte->virtual_address) == true){
      pagedir_set_accessed(clock_current_page->t->pagedir, clock_current_page->vte->virtual_address, 0);
    }
    else{
      //if(clock_list_lock.holder != NULL)
      //  printf(" **** /file.c : evict_clock_page - clock lock thread tid : %d, lock holder tid : %d\n", thread_current()->tid, clock_list_lock.holder->tid);
      lock_acquire(&(clock_list_lock));
      victim_page = clock_current_page;
      break;
    }
  }
 
  if(victim_page->vte->source_type == VM_BINARY){
    if(pagedir_is_dirty(clock_current_page->t->pagedir, clock_current_page->vte->virtual_address) == true){
      victim_page->vte->swap_slot = swap_out(victim_page->physical_address);
      victim_page->vte->source_type = VM_SWAP;
    }
  }
  else if(victim_page->vte->source_type == VM_MMAPFILE){
    if(pagedir_is_dirty(clock_current_page->t->pagedir, clock_current_page->vte->virtual_address) == true){
      //if(syscall_get_filesys_lock()->holder != NULL)
      //  printf(" **** /file.c : evict_clock_page - filesys lock thread tid : %d, lock holder tid : %d\n", thread_current()->tid, syscall_get_filesys_lock()->holder->tid);
      lock_acquire(syscall_get_filesys_lock());
      file_write_at(clock_current_page->vte->file, clock_current_page->vte->virtual_address, clock_current_page->vte->page_bytes, clock_current_page->vte->offset);
      lock_release(syscall_get_filesys_lock());
    }
  }
  else if(victim_page->vte->source_type == VM_SWAP){
    victim_page->vte->swap_slot = swap_out(victim_page->physical_address);
  }
  victim_page->vte->isLoaded = false;
  pagedir_clear_page(victim_page->t->pagedir, victim_page->vte->virtual_address);
  palloc_free_page(victim_page->physical_address);
  list_remove(&(victim_page->clock_elem));
  free(clock_current_page);
 
  lock_release(&(clock_list_lock));
}













