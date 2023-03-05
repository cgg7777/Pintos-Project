#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"
#include "vm/file.h"
#include "vm/swap.h"

struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);

static struct virtual_table_entry* check_vaddr(const void *);
static void check_buffer(void *buffer, unsigned size, bool isWriteable);
static void check_string(const void *str);

static void syscall_halt(void);
static pid_t syscall_exec(const char *);
static int syscall_wait(pid_t);
static bool syscall_create(const char *, unsigned);
static bool syscall_remove(const char *);
static int syscall_open(const char *);
static int syscall_filesize(int);
static int syscall_read(int, void *, unsigned);
static int syscall_write(int, const void *, unsigned);
static void syscall_seek(int, unsigned);
static unsigned syscall_tell(int);

/* Registers the system call interrupt handler. */
void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

/* Pops the system call number and handles system call
   according to it. */
static void
syscall_handler(struct intr_frame *f)
{
    void *esp = f->esp;
    int syscall_num;

    check_vaddr(esp);
    //check_vaddr(esp + sizeof(uintptr_t) - 1);
    syscall_num = *(int *)esp;

    switch (syscall_num)
    {
    case SYS_HALT:
    {
        syscall_halt();
        NOT_REACHED();
    }
    case SYS_EXIT:
    {
        int status;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        status = *(int *)(esp + sizeof(uintptr_t));

        syscall_exit(status);
        NOT_REACHED();
    }
    case SYS_EXEC:
    {
        char *cmd_line;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        cmd_line = *(char **)(esp + sizeof(uintptr_t));
        
        check_string(cmd_line);

        f->eax = (uint32_t)syscall_exec(cmd_line);
        break;
    }
    case SYS_WAIT:
    {
        pid_t pid;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        pid = *(pid_t *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_wait(pid);
        break;
    }
    case SYS_CREATE:
    {
        char *file;
        unsigned initial_size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));
        initial_size = *(unsigned *)(esp + 2 * sizeof(uintptr_t));
        
        check_string(file);

        f->eax = (uint32_t)syscall_create(file, initial_size);
        break;
    }
    case SYS_REMOVE:
    {
        char *file;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_remove(file);
        break;
    }
    case SYS_OPEN:
    {
        char *file;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));
        
        check_string(file);

        f->eax = (uint32_t)syscall_open(file);
        break;
    }
    case SYS_FILESIZE:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_filesize(fd);
        break;
    }
    case SYS_READ:
    {
        int fd;
        void *buffer;
        unsigned size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 1 * sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t));
        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));
        
        // TODO : why isWriteable is true?
        check_buffer(buffer, size, true);

        f->eax = (uint32_t)syscall_read(fd, buffer, size);
        break;
    }
    case SYS_WRITE:
    {
        int fd;
        void *buffer;
        unsigned size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 4 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));
        
        // TODO : why isWriteable is false?
        check_buffer(buffer, size, false);

        f->eax = (uint32_t)syscall_write(fd, buffer, size);
        break;
    }
    case SYS_SEEK:
    {
        int fd;
        unsigned position;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        position = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        syscall_seek(fd, position);
        break;
    }
    case SYS_TELL:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_tell(fd);
        break;
    }
    case SYS_CLOSE:
    {
        int fd;
        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        syscall_close(fd);
        break;
    }
    case SYS_MMAP:
    {
	int fd;
	void *buffer;
        
	check_vaddr(esp + sizeof(uintptr_t));
	check_vaddr(esp + 2 * sizeof(uintptr_t));
	check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
	
	fd = *(int *)(esp + sizeof(uintptr_t));
	buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        
	f->eax = mapping_memory(fd, buffer);

	break;
    }
    case SYS_MUNMAP:
    {
        int fd;
        
	check_vaddr(esp + sizeof(uintptr_t));
	check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        
	fd = *(int *)(esp + sizeof(uintptr_t));
	unmapping_memory(fd);

	break;
    }
    default:
        syscall_exit(-1);
    }

}

/* Checks user-provided virtual address. If it is
   invalid, terminates the current process. */
static struct virtual_table_entry* check_vaddr(const void *vaddr)
{
    if (!vaddr || is_user_vaddr(vaddr) == false || is_kernel_vaddr(vaddr) == true)
        syscall_exit(-1);
        
    return find_virtual_entry(vaddr);
}

static void check_buffer(void *buffer, unsigned size, bool isWriteable){
  struct virtual_table_entry *vte;
  void *buffer_address = buffer;
  int i;
  
  for(i = 0; i<size; i++, buffer_address++){
    vte = check_vaddr(buffer_address);
    if(vte == NULL){
      syscall_exit(-1);
    }
    else{
      if(isWriteable == true && vte->isWriteable == false){
        syscall_exit(-1);
      }
    }
  }
}

static void check_string(const void *str){
  struct virtual_table_entry *vte;
  char *str_address = str;
  
  while(*str_address != '\0'){
    vte = check_vaddr(str_address);
    if(vte == NULL){
      syscall_exit(-1);
    }
    else{
      str_address++;
    }
  }
}

struct lock *syscall_get_filesys_lock(void)
{
    return &filesys_lock;
}

/* Handles halt() system call. */
static void syscall_halt(void)
{
    shutdown_power_off();
}

/* Handles exit() system call. */
void syscall_exit(int status)
{
    struct process *pcb = thread_get_pcb();
    
    //printf(" **** syscall exit , exit tid : %d\n", thread_current()->tid);

    pcb->exit_status = status;
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_exit();
}

/* Handles exec() system call. */
static pid_t syscall_exec(const char *cmd_line)
{
    pid_t pid;
    struct process *child;
    int i;

    check_vaddr(cmd_line);
    for (i = 0; *(cmd_line + i); i++)
        check_vaddr(cmd_line + i + 1);

    pid = process_execute(cmd_line);
    child = process_get_child(pid);

    if (!child || !child->is_loaded)
        return PID_ERROR;

    return pid;
}

/* Handles wait() system call. */
static int syscall_wait(pid_t pid)
{
    //printf("**** proceess wait\n");
    return process_wait(pid);
}

/* Handles create() system call. */
static bool syscall_create(const char *file, unsigned initial_size)
{
    bool success;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);
        
    //if(filesys_lock.holder != NULL)
    //  printf(" **** /syscall.c : syscall_create - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);

    lock_acquire(&filesys_lock);
    success = filesys_create(file, (off_t)initial_size);
    lock_release(&filesys_lock);

    return success;
}

/* Handles remove() system call. */
static bool syscall_remove(const char *file)
{
    bool success;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    //if(filesys_lock.holder != NULL)
    //  printf(" **** /syscall.c : syscall_remove - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
    
    lock_acquire(&filesys_lock);
    success = filesys_remove(file);
    lock_release(&filesys_lock);

    return success;
}

/* Handles open() system call. */
static int syscall_open(const char *file)
{
    struct file_descriptor_entry *fde;
    struct file *new_file;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    fde = palloc_get_page(0);
    if (!fde)
        return -1;

    //if(filesys_lock.holder != NULL)
    //  printf(" **** /syscall.c : syscall_open - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
    
    lock_acquire(&filesys_lock);

    new_file = filesys_open(file);
    if (!new_file)
    {
        palloc_free_page(fde);
        lock_release(&filesys_lock);

        return -1;
    }

    fde->fd = thread_get_next_fd();
    fde->file = new_file;
    list_push_back(thread_get_fdt(), &fde->fdtelem);

    lock_release(&filesys_lock);

    return fde->fd;
}

/* Handles filesize() system call. */
static int syscall_filesize(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);
    int filesize;

    if (!fde)
        return -1;

    //if(filesys_lock.holder != NULL)
    //  printf(" **** /syscall.c : syscall_filesize - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
    
    lock_acquire(&filesys_lock);
    filesize = file_length(fde->file);
    lock_release(&filesys_lock);

    return filesize;
}

/* Handles read() system call. */
static int syscall_read(int fd, void *buffer, unsigned size)
{
    struct file_descriptor_entry *fde;
    int bytes_read, i;

    for (i = 0; i < size; i++)
        check_vaddr(buffer + i);

    if (fd == 0)
    {
        unsigned i;

        for (i = 0; i < size; i++)
            *(uint8_t *)(buffer + i) = input_getc();

        return size;
    }

    fde = process_get_fde(fd);
    if (!fde)
        return -1;

    //if(filesys_lock.holder != NULL)
    //  printf(" **** /syscall.c : syscall_read - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
    
    lock_acquire(&filesys_lock);
    bytes_read = (int)file_read(fde->file, buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_read;
}

/* Handles write() system call. */
static int syscall_write(int fd, const void *buffer, unsigned size)
{
    struct file_descriptor_entry *fde;
    int bytes_written, i;

    for (i = 0; i < size; i++)
        check_vaddr(buffer + i);

    if (fd == 1)
    {
        putbuf((const char *)buffer, (size_t)size);

        return size;
    }

    fde = process_get_fde(fd);
    if (!fde)
        return -1;

    //if(filesys_lock.holder != NULL)
    //  printf(" **** /syscall.c : syscall_write - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
    
    lock_acquire(&filesys_lock);
    bytes_written = (int)file_write(fde->file, buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_written;
}

/* Handles seek() system call. */
static void syscall_seek(int fd, unsigned position)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);

    if (!fde)
        return;

    //if(filesys_lock.holder != NULL)
    //  printf(" **** /syscall.c : syscall_seek - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
      
    lock_acquire(&filesys_lock);
    file_seek(fde->file, (off_t)position);
    lock_release(&filesys_lock);
}

/* Handles tell() system call. */
static unsigned syscall_tell(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);
    unsigned pos;

    if (!fde)
        return -1;

    //if(filesys_lock.holder != NULL)
    //  printf(" **** /syscall.c : syscall_tell - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
    
    lock_acquire(&filesys_lock);
    pos = (unsigned)file_tell(fde->file);
    lock_release(&filesys_lock);

    return pos;
}

/* Handles close() system call. */
void syscall_close(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);

    if (!fde)
        return;

    //if(filesys_lock.holder != NULL)
    //  printf(" **** /syscall.c : syscall_close - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
    
    lock_acquire(&filesys_lock);
    file_close(fde->file);
    list_remove(&fde->fdtelem);
    palloc_free_page(fde);
    lock_release(&filesys_lock);
}


int mapping_memory(int fd, void *virtual_address){
  if(!virtual_address || is_user_vaddr(virtual_address) == false || ((uint32_t)(virtual_address))%PGSIZE != 0){
    return -1;
  }

  struct file_descriptor_entry* file_des_ent = process_get_fde(fd);
  struct file *reopened_file = file_reopen(file_des_ent->file);
  if(reopened_file == NULL){
    return -1;
  }
  struct memory_mapped_file *mmf_entry = malloc(sizeof(struct memory_mapped_file));
  if(mmf_entry == NULL){
    return -1;
  }
  mmf_entry->id = thread_current()->next_mmfid;
  mmf_entry->file = reopened_file;
  list_init(&(mmf_entry->vte_list));
  thread_current()->next_mmfid = thread_current()->next_mmfid + 1;
  // copy from process.c : load_segment
  int read_bytes = file_length(mmf_entry->file);
  int32_t ofs = 0;
  while (read_bytes > 0){
        /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;
        
        struct virtual_table_entry *vte = (struct virtual_table_entry *)malloc(sizeof(struct virtual_table_entry));
        if(vte == NULL) {
          return -1;
        }
        vte->source_type = VM_MMAPFILE;
        vte->virtual_address = virtual_address;
        vte->offset = ofs;
        //printf(" **** src/userprog/syscall.c : mapping_memory - vte->offset : %d\n", vte->offset);
        vte->page_bytes = page_read_bytes;
        vte->align_bytes = page_zero_bytes;
        vte->isLoaded = false;
        vte->isWriteable = true;
        vte->swap_slot = 0;
        vte->file = reopened_file;
        
        if(insert_virtual_entry(&(thread_current()->thread_vm_hash_table), vte) == false){
          //printf(" **** /userprog/syscall.c : insert_virtual_memory. insert is failed\n");
          return -1;
        }
        //printf(" **** /userprog/syscall.c : insert_virtual_memory. vte->virtual_address : %x\n", vte->virtual_address);
       
        /* Advance. */
        read_bytes -= page_read_bytes;
        ofs += page_read_bytes;
        virtual_address += PGSIZE;
        
        list_push_back(&(mmf_entry->vte_list), &(vte->vte_mmfelem));
 }
 
  list_push_back(&(thread_current()->mmf_list), &(mmf_entry->mmf_elem));
  
  return mmf_entry->id;
}

void unmapping_memory(int mmfid){
  struct list_elem *iter;
  
  for(iter = list_begin(&(thread_current()->mmf_list)); iter != list_end(&(thread_current()->mmf_list));){
    struct memory_mapped_file *mmf = list_entry(iter, struct memory_mapped_file, mmf_elem);
    
    if(mmfid < 0 || mmf->id == mmfid){
      unmapping_file(mmf);
      //if(filesys_lock.holder != NULL)
      //  printf(" **** /syscall.c : unmapping_memory - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
      lock_acquire(&filesys_lock);
      file_close(mmf->file);
      lock_release(&filesys_lock);
      iter = list_remove(iter);
      free(mmf);
    }
    else{
      iter = list_next(iter);
    }
  }
}

void unmapping_file(struct memory_mapped_file *mmf){
  struct list_elem *iter;

  for(iter = list_begin(&(mmf->vte_list)); iter != list_end(&(mmf->vte_list));){

    struct virtual_table_entry *vte = list_entry(iter, struct virtual_table_entry, vte_mmfelem);

    // if loaded on memory then remove it
    if(vte->isLoaded == true){
      // if dirty
      if(pagedir_is_dirty(thread_current()->pagedir, vte->virtual_address) == true){
        //if(filesys_lock.holder != NULL)
        //  printf(" **** /syscall.c : unmapping_file - thread tid : %d, lock holder tid : %d\n", thread_current()->tid, filesys_lock.holder->tid);
        lock_acquire(&filesys_lock);
        file_write_at(vte->file, vte->virtual_address, vte->page_bytes, vte->offset);
        lock_release(&filesys_lock);
      }
      void *page_physical_address = pagedir_get_page(thread_current()->pagedir, vte->virtual_address);
      // remove it from page directory
      //printf(" **** in \n");
      //printf(" **** in \n");
      //printf(" **** in \n");
      
      pagedir_clear_page(thread_current()->pagedir, vte->virtual_address);
      
      //printf(" **** in1 \n");
      //printf(" **** in1 \n");
      //printf(" **** in1 \n");
      // and free from physical memory
      alloc_free_page(page_physical_address);
      // remove from memory and free it
      iter = list_remove(iter);
      delete_virtual_entry(&(thread_current()->thread_vm_hash_table), vte);
    }
    else{
      iter = list_next(iter);
    }
  }
}

