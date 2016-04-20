#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/exception.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

struct lock file_lock;
static inline uint32_t nth_arg(struct intr_frame *f, int n);
static inline bool is_valid(void *pointer);
static inline void bad_esp_filter(struct intr_frame *f, int num_of_arg);

static void syscall_handler (struct intr_frame *);
static void sys_halt(struct intr_frame *);
static void sys_exit(struct intr_frame *);
static void sys_exec(struct intr_frame *);
static void sys_wait(struct intr_frame *);
static void sys_create(struct intr_frame *);
static void sys_remove(struct intr_frame *);
static void sys_open(struct intr_frame *);
static void sys_filesize(struct intr_frame *);
static void sys_read(struct intr_frame *);
static void sys_write(struct intr_frame *);
static void sys_seek(struct intr_frame *);
static void sys_tell(struct intr_frame *);
static void sys_close(struct intr_frame *);
static struct thread_filesys *lookup_fd(struct thread *t, int fd);

void
syscall_init (void)
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{

  int syscall_num = *(int32_t **)(f->esp);

  switch(syscall_num)
  {
    case SYS_HALT:
      sys_halt(f);
      break;

    case SYS_EXIT:
      sys_exit(f);
      break;

    case SYS_EXEC:
      sys_exec(f);
      break;

    case SYS_WAIT:
      sys_wait(f);
      break;

    case SYS_CREATE:
      sys_create(f);
      break;

    case SYS_REMOVE:
      sys_remove(f);
      break;

    case SYS_OPEN:
      sys_open(f);
      break;

    case SYS_FILESIZE:
      sys_filesize(f);
      break;

    case SYS_READ:
      sys_read(f);
      break;

    case SYS_WRITE:
      sys_write(f);
      break;

    case SYS_SEEK:
      sys_seek(f);
      break;

    case SYS_TELL:
      sys_tell(f);
      break;

    case SYS_CLOSE:
      sys_close(f);
      break;

    default:
      NOT_REACHED();
      break;
  }
}


static inline void
bad_esp_filter(struct intr_frame *f, int n)
{
  if((((int32_t *)f->esp) + n + 1) > PHYS_BASE)
    page_fault(f);
}

static inline uint32_t
nth_arg(struct intr_frame *f, int n)
{
  return *(((uint32_t *)f->esp) + n);
}

static inline bool
is_valid(void *pointer)
{
  return (pointer < PHYS_BASE) && (pointer);
}


static void
sys_halt(struct intr_frame *f)
{
  bad_esp_filter(f, 0);
  power_off();
}

static void
sys_exit(struct intr_frame *f)
{
  bad_esp_filter(f, 1);
  int status = nth_arg(f, 1);
//  if(lock_held_by_current_thread(&file_lock))
//      lock_release(&file_lock);
  thread_current()->exit_status = status;
  thread_exit();
}

static void
sys_exec(struct intr_frame *f)
{
  bad_esp_filter(f, 1);
  const char *cmd_line = nth_arg(f, 1);
  pid_t pid;

  if(is_valid(cmd_line)){
    pid = process_execute(cmd_line);
    f->eax = pid;
  }
  else
    page_fault(f);
}

static void
sys_wait(struct intr_frame *f)
{
  bad_esp_filter(f, 1);
  pid_t pid = nth_arg(f, 1);
  f->eax = process_wait(pid);
}

static void
sys_create(struct intr_frame *f)
{
  bad_esp_filter(f, 2);
  const char *file = nth_arg(f, 1);
  unsigned initial_size = nth_arg(f, 2);
  bool create;

  if(is_valid(file)){
//    lock_acquire(&file_lock);
    create = filesys_create(file, initial_size);
    f->eax = create;
//    lock_release(&file_lock);
  }
  else
    page_fault(f);
}

static void
sys_remove(struct intr_frame *f)
{
  bad_esp_filter(f, 1);
  const char *file = nth_arg(f, 1);
  bool remove;

  if(is_valid(file)){
//    lock_acquire(&file_lock);
    remove = filesys_remove(file);
    f->eax = remove;
//    lock_release(&file_lock);
  }
  else
    page_fault(f);
}

static void
sys_open(struct intr_frame *f)
{
  bad_esp_filter(f, 1);
  const char *file = nth_arg(f, 1);

  if(is_valid(file)){
//    lock_acquire(&file_lock);
    int fd;
    struct thread *t = thread_current();
    struct thread_filesys *tf = malloc(sizeof(struct thread_filesys));
    struct file *of = filesys_open(file);

    if(of){
      fd = t->maxfd + 1;
      t->maxfd = fd;
      tf->fd = fd;
      tf->file = of;
      list_push_back(&t->open_files, &tf->elem);
    }
    else{
      fd = -1;
      free(tf);
    }
    f->eax = fd;
//    lock_release(&file_lock);
  }
  else
    page_fault(f);
}

static void
sys_filesize(struct intr_frame *f)
{
  bad_esp_filter(f, 1);
  int fd = nth_arg(f, 1);
  int size;
//  lock_acquire(&file_lock);
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf)
    size = file_length(tf->file);
  else
    size = 0;
  f->eax = size;
//  lock_release(&file_lock);
}

static void
sys_read(struct intr_frame *f)
{
  bad_esp_filter(f, 3);
  int fd = nth_arg(f, 1);
  void *buffer = nth_arg(f, 2);
  unsigned size = nth_arg(f, 3);
  int result;

  if(is_valid(buffer)){
//    lock_acquire(&file_lock);
    if(fd == 0){
      input_getc();
    }
    else{
      struct thread *t = thread_current();
      struct thread_filesys *tf = lookup_fd(t, fd);
      if(tf){
        result = file_read(tf->file, buffer, size);
      }
      else
        result = -1;
      f->eax = result;
    }
//    lock_release(&file_lock);
  }
  else
    page_fault(f);
}

static void
sys_write(struct intr_frame *f)
{
  bad_esp_filter(f, 3);
  int fd = nth_arg(f, 1);
  const void *buffer = nth_arg(f, 2);
  unsigned size = nth_arg(f, 3);
  int result;

  if(is_valid(buffer)){
//    lock_acquire(&file_lock);
    if(fd == 1){
      putbuf(buffer, size);
    }
    else{
      struct thread *t = thread_current();
      struct thread_filesys *tf = lookup_fd(t, fd);
      if(tf){
        result = file_write(tf->file, buffer, size);
      }
      else
        result = -1;
      f->eax = result;
    }
//    lock_release(&file_lock);
  }
  else
    page_fault(f);
}

static void
sys_seek(struct intr_frame *f)
{
  bad_esp_filter(f, 2);
  int fd = nth_arg(f, 1);
  unsigned position = nth_arg(f, 2);

//  lock_acquire(&file_lock);
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf)
    file_seek(tf->file, position);
//  lock_release(&file_lock);
}

static void
sys_tell(struct intr_frame *f)
{
  bad_esp_filter(f, 1);
  int fd = nth_arg(f, 1);
  unsigned result;

//  lock_acquire(&file_lock);
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf){
    result = file_tell(fd);
  }
  else
    result = -1;
  f->eax = result;
//  lock_release(&file_lock);
}

static void
sys_close(struct intr_frame *f)
{
  bad_esp_filter(f, 1);
  int fd = nth_arg(f, 1);

//  lock_acquire(&file_lock);
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);

  if(tf){
    file_close(tf->file);
    list_remove(&tf->elem);
    free(tf);
  }
//  lock_release(&file_lock);
}


static struct thread_filesys
*lookup_fd(struct thread *t, int fd)
{
  struct list_elem *e;
  for(e = list_begin(&t->open_files); e != list_end(&t->open_files); e = list_next(e)){
    struct thread_filesys *tf = list_entry(e, struct thread_filesys, elem);
    if(tf->fd == fd)
      return tf;
  }
  // not found.
  return NULL;
}

