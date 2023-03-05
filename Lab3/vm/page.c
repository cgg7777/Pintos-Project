#include "page.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

static unsigned vm_hash_function(const struct hash_elem *e, void *aux);
static bool vm_less_compare(const struct hash_elem *a, const struct hash_elem *b);

void vm_init(struct hash *thread_vm_hash){
  hash_init(thread_vm_hash, vm_hash_function, vm_less_compare, NULL);
}


static unsigned vm_hash_function(const struct hash_elem *e, void *aux){
  struct virtual_table_entry *temp;
  temp = hash_entry(e, struct virtual_table_entry, vte_hashelem);
  return hash_int(temp->virtual_address);
}


static bool vm_less_compare(const struct hash_elem *a, const struct hash_elem *b){
  struct virtual_table_entry *aentry, *bentry;
  aentry = hash_entry(a, struct virtual_table_entry, vte_hashelem);
  bentry = hash_entry(b, struct virtual_table_entry, vte_hashelem);
  
  if(aentry->virtual_address < bentry->virtual_address){
    return true;
  }
  else{
    return false;
  }
}

bool insert_virtual_entry(struct hash *thread_vm_hash, struct virtual_table_entry *vte){
  //printf(" **** /vm/page.c : insert_virtual_entry - vte->vitrual_address : %x\n", vte->virtual_address);
  bool result = hash_insert(thread_vm_hash, &(vte->vte_hashelem));
  if(result == NULL)
    return true;
  else
    return false;
  
}

bool delete_virtual_entry(struct hash *thread_vm_hash, struct virtual_table_entry *vte){
  bool result = hash_delete(thread_vm_hash, &(vte->vte_hashelem));
  if(result == NULL){
    return false;
  }
  else{
    return true;
  }
}

struct virtual_table_entry* find_virtual_entry(void *virtual_address){
  struct virtual_table_entry temp;
  struct hash_elem *temp_hash;
  
  
  temp.virtual_address = pg_round_down(virtual_address);
  temp_hash = hash_find(&(thread_current()->thread_vm_hash_table), &(temp.vte_hashelem));
  if(temp_hash == NULL){
    // if not found, return null
    //printf(" ****** /vm/page.c : find_virtual_entry - not found\n");
    return NULL;
  }
  else{
    //printf(" ****** /vm/page.c : find_virtual_entry - find results : %x\n", hash_entry(temp_hash, struct virtual_table_entry, vte_hashelem)->virtual_address);
    return hash_entry(temp_hash, struct virtual_table_entry, vte_hashelem);
  }
}

void destroy_hash_entry(struct hash *thread_vm_hash){
  hash_destroy(thread_vm_hash, destroy_function);
}

void destroy_function(struct hash_elem *e, void *aux UNUSED){
  struct virtual_table_entry *vte = hash_entry(e, struct virtual_table_entry, vte_hashelem); 
  if(vte->isLoaded == true){
    void *physical_address = pagedir_get_page(thread_current()->pagedir, vte->virtual_address);
    alloc_free_page(physical_address);
    pagedir_clear_page(thread_current()->pagedir, vte->virtual_address);
  }
  free(vte);
}

bool load_from_disk(void *new_page_address, struct virtual_table_entry *vte){
  bool success;
  //printf(" **** /vm/page.c : load_from_disk - vte->offset : %d\n", vte->offset);
  off_t readbyte = file_read_at(vte->file, new_page_address, vte->page_bytes, vte->offset);
  if(readbyte != vte->page_bytes){
    success = false;
  }
  else{
    success = true;
    memset(new_page_address + vte->page_bytes, 0, vte->align_bytes);
  }
  //printf(" **** /vm/page.c : load_from_disk - sucesss : %d\n", success);
  //printf(" **** /vm/page.c : load_from_disk - vte->offset : %d\n", vte->offset);
  return success;
  
}





















