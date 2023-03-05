#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "vm/page.h"

void syscall_init(void);

struct lock *syscall_get_filesys_lock(void);

void syscall_exit(int);
void syscall_close(int);
int mapping_memory(int fd, void *virtual_address);
void unmapping_memory(int mmfid);
void unmapping_file(struct memory_mapped_file *mmf);

#endif /* userprog/syscall.h */
