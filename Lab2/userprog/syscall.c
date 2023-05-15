#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "string.h"

typedef int pid_t;
struct lock file_lock;

static void syscall_handler (struct intr_frame *);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait (pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
bool isValidPointer(void *esp);
void pop_argument(void *esp, int *argv, int argc);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  
  // printf ("system call!\n");
  
  
  if(!isValidPointer(f->esp))
    exit(-1);
  
  
  int syscall_num = *(uint32_t*)(f->esp);
  int argv[4];
  
  //printf ("syscall num : %d\n", syscall_num);
  //hex_dump(f->esp, f->esp, 100, true);

  
  
  switch(*(uint32_t*)(f->esp)){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      pop_argument(f->esp, &argv[0], 1);
      exit(argv[0]);
      break;
    case SYS_EXEC:
      pop_argument(f->esp, &argv[0], 1);
      f->eax = exec((char*)argv[0]);
      break;
    case SYS_WAIT:
      pop_argument(f->esp, &argv[0], 1);
      f->eax = wait((pid_t)argv[0]);
      break;
    case SYS_CREATE:
      pop_argument(f->esp, &argv[0], 2);
      f->eax = create((char*)argv[0], argv[1]);
      break;
    case SYS_REMOVE:
      pop_argument(f->esp, &argv[0], 1);
      f->eax = remove((char*)argv[0]);
      break;
    case SYS_OPEN:
      pop_argument(f->esp, &argv[0], 1);
      f->eax = open((char*)argv[0]);
      break;
    case SYS_FILESIZE:
      pop_argument(f->esp, &argv[0], 1);
      f->eax = filesize((int)argv[0]);
      break;
    case SYS_READ:
      pop_argument(f->esp, &argv[0], 3);
      f->eax = read((int)argv[0], (void*)argv[1], (unsigned)argv[2]);
      break;
    case SYS_WRITE:
      pop_argument(f->esp, &argv, 3);
      f->eax = write((int)argv[0], (void*)argv[1], (unsigned)argv[2]);
      break;
    case SYS_SEEK:
      pop_argument(f->esp, &argv[0], 2);
      seek((int)argv[0], (unsigned)argv[1]);
      break;
    case SYS_TELL:
      pop_argument(f->esp, &argv[0], 1);
      f->eax = tell((int)argv[0]);
      break;
    case SYS_CLOSE:
      pop_argument(f->esp, &argv[0], 1);
      close((int)argv[0]);
      break;
      
  }
  //thread_exit ();
}

void halt(void){
  shutdown_power_off();
}

void exit(int status){
  //printf(" - exit, tid : %d, status : %d\n", thread_current()->tid, status);
  
  thread_current() -> exit_status = status;
  
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
  
  
}

pid_t exec(const char *cmd_line){
  if(!isValidPointer(cmd_line))
    exit(-1);
    
  
  int child_pid = process_execute(cmd_line);
  
  
  struct thread *child_thread = find_child_thread(child_pid);
  if(child_thread == NULL || child_thread->isLoaded == false)
    return -1;
  
  
  return child_pid;
}

int wait (pid_t pid){
  /*
  struct thread *t = find_child_thread(pid);
  if(t == NULL) return -1;
  while(1){
    if(t->isTerminated == false){
      thread_yield();
    }
    if(thread_current()->exit_status == -1)
      printf(" - wait, tid : %d, status : %d\n", thread_current()->tid, thread_current()->exit_status);
    if(t->isTerminated == true)
      break;
      
  }*/
  
  
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size){
  if(!isValidPointer(file))
    exit(-1);
  return filesys_create(file, initial_size);
}

bool remove(const char *file){
  if(!isValidPointer(file) || file == NULL)
    exit(-1);
  return filesys_remove(file);
}

int open(const char *file){
  int i;
  
  if(!isValidPointer(file))
    exit(-1);
  lock_acquire(&file_lock);
  struct file *open_file = filesys_open(file);
  if(open_file == NULL){
    lock_release(&file_lock);
    return -1;
  }  
  i = add_file(open_file,file);
  lock_release(&file_lock);
  return i;
}

int filesize(int fd){
  struct file *size_file = get_file(fd);
  if(size_file == NULL)
    exit(-1);
  return file_length(size_file);
}

int read(int fd, void *buffer, unsigned size){
  int i;
  struct file* read_file;
  if(!isValidPointer(buffer))
    exit(-1);
  
  lock_acquire(&file_lock);
  if(fd == 0){
    for(i = 0; i<size; i++){
      if(((char*)buffer) + i == '\0')
        break;
    }
    lock_release(&file_lock);
  }
  else{
    read_file = get_file(fd);
    if(read_file == NULL){
      lock_release(&file_lock);
      exit(-1);
    }
    
    i = file_read(read_file, buffer, size);
    lock_release(&file_lock);
  }
  return i;
}

int write(int fd, const void *buffer, unsigned size){
  struct file* write_file;
  int i;
  
  if(!isValidPointer(buffer))
    exit(-1);
    
  lock_acquire(&file_lock);
  
  if(fd == 1){
    putbuf(buffer, size);
    lock_release(&file_lock);
    //printf(" - in write, buffer : %s, size : %d\n", buffer, size);
    return size;
  }
  else{
    write_file = get_file(fd);
    if(write_file == NULL){
      lock_release(&file_lock);
      exit(-1);
    }
      
    i = file_write(write_file, buffer, size);
    lock_release(&file_lock);
    return i;
  }
}

void seek(int fd, unsigned position){
  struct file* seek_file = get_file(fd);
  if(seek_file == NULL)
    exit(-1);
  return file_seek(seek_file, position);
}

unsigned tell(int fd){
  struct file* tell_file = get_file(fd);
  if(tell_file == NULL)
    exit(-1);
  return file_tell(tell_file);
}

void close(int fd){
  close_file(fd);
  return;
}



// check whether intr_frame's stack pointer is in user stack
bool isValidPointer(void *esp){
  if(is_user_vaddr(esp) == false || is_kernel_vaddr(esp) == true || esp == NULL){
    exit(-1);
    }
  else
    return true;
}

void pop_argument(void *esp, int *argv, int argc){
  int i;  
  //printf(" - pop argument in! esp : %x\n", esp);
  for(i = 0; i<argc; i++){
    if(!isValidPointer(esp + 4 + 4*i))
      exit(-1);
    argv[i] = *(uint32_t*)(esp + 4 + 4*i);
    //printf(" - pop argument %dth : %x | %x from %x\n", i, argv[i], *(uint32_t*)(esp+4+4*i), (uint32_t*)(esp+4+4*i));
  }
  return;
}























