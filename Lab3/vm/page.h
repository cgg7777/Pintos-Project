#ifndef PAGE_H
#define PAGE_H

#include <hash.h>

#define VM_BINARY 0
#define VM_MMAPFILE 1
#define VM_SWAP 2

struct virtual_table_entry{
  int source_type;
  void *virtual_address;
  
  size_t offset;
  size_t page_bytes;
  size_t align_bytes;
  
  bool isWriteable;
  bool isLoaded;
  size_t swap_slot;
  
  struct hash_elem vte_hashelem;
  struct list_elem vte_mmfelem;
  struct file* file;
};

struct memory_mapped_file{
  int id;		// identifier
  struct file *file;
  struct list vte_list;
  struct list_elem mmf_elem;
};

struct page{
  void *physical_address;
  struct virtual_table_entry *vte;
  struct thread *t;
  struct list_elem clock_elem;
};

void vm_init(struct hash *thread_vm_hash);
bool insert_virtual_entry(struct hash *thread_vm_hash, struct virtual_table_entry *vte);
bool delete_virtual_entry(struct hash *thread_vm_hash, struct virtual_table_entry *vte);
struct virtual_table_entry* find_virtual_entry(void *virtual_address);
void destroy_hash_entry(struct hash *thread_vm_hash);
void destroy_function(struct hash_elem *, void *);
bool load_from_disk(void *new_page_address, struct virtual_table_entry *vte);

#endif /* vm/page.h */
