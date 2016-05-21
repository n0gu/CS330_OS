#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/exception.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "lib/user/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

struct lock file_lock;
static inline uint32_t nth_arg(struct intr_frame *f, int n);
static inline bool is_valid(void *pointer);
static inline void bad_esp_filter(struct intr_frame *f, int num_of_arg);

static void syscall_handler (struct intr_frame *);
static void sys_halt(void);
static void sys_exit(int);
static pid_t sys_exec(const char *);
static int sys_wait(pid_t);
static bool sys_create(const char *, unsigned);
static bool sys_remove(const char *);
static int sys_open(const char *);
static int sys_filesize(int);
static int sys_read(int, void *, unsigned);
static int sys_write(int, const void *, unsigned);
static void sys_seek(int, unsigned);
static unsigned sys_tell(int);
static void sys_close(int);
static mapid_t sys_mmap(int, void *);
static void sys_munmap(mapid_t);
static struct thread_filesys *lookup_fd(struct thread *, int);
static struct thread_mmap *lookup_mapid(struct thread *, mapid_t);

void
syscall_init (void)
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  int status, fd;
  char *cmd_line, *file;
  pid_t pid;
  mapid_t mapid;
  unsigned size, position;
  void *buffer;

  int syscall_num = *(int32_t *)(f->esp);
  thread_current()->syscall_esp = f->esp;

  switch(syscall_num)
  {
    case SYS_HALT:
      sys_halt();
      break;

    case SYS_EXIT:
      bad_esp_filter(f, 1);
      status = nth_arg(f, 1);
      sys_exit(status);
      break;

    case SYS_EXEC:
      bad_esp_filter(f, 1);
      cmd_line = (char *)nth_arg(f, 1);
      f->eax = sys_exec(cmd_line);
      break;

    case SYS_WAIT:
      bad_esp_filter(f, 1);
      pid = nth_arg(f, 1);
      f->eax = sys_wait(pid);
      break;

    case SYS_CREATE:
      bad_esp_filter(f, 2);
      file = (char *)nth_arg(f, 1);
      size = nth_arg(f, 2);
      f->eax = sys_create(file, size);
      break;

    case SYS_REMOVE:
      bad_esp_filter(f, 1);
      file = (char *)nth_arg(f, 1);
      f->eax = sys_remove(file);
      break;

    case SYS_OPEN:
      bad_esp_filter(f, 1);
      file = (char *)nth_arg(f, 1);
      f->eax = sys_open(file);
      break;

    case SYS_FILESIZE:
      bad_esp_filter(f, 1);
      fd = nth_arg(f, 1);
      f->eax = sys_filesize(fd);
      break;

    case SYS_READ:
      bad_esp_filter(f, 3);
      fd = nth_arg(f, 1);
      buffer = nth_arg(f, 2);
      size = nth_arg(f, 3);
      f->eax = sys_read(fd, buffer, size);
      break;

    case SYS_WRITE:
      bad_esp_filter(f, 3);
      fd = nth_arg(f, 1);
      buffer = nth_arg(f, 2);
      size = nth_arg(f, 3);
      f->eax = sys_write(fd, buffer, size);
      break;

    case SYS_SEEK:
      bad_esp_filter(f, 2);
      fd = nth_arg(f, 1);
      position = nth_arg(f, 2);
      sys_seek(fd, position);
      break;

    case SYS_TELL:
      bad_esp_filter(f, 1);
      fd = nth_arg(f, 1);
      f->eax = sys_tell(fd);
      break;

    case SYS_CLOSE:
      bad_esp_filter(f, 1);
      fd = nth_arg(f, 1);
      sys_close(fd);
      break;

    case SYS_MMAP:
      bad_esp_filter(f, 2);
      fd = nth_arg(f, 1);
      buffer = nth_arg(f, 2);
      f->eax = sys_mmap(fd, buffer);
      break;

    case SYS_MUNMAP:
      bad_esp_filter(f, 1);
      mapid = nth_arg(f, 1);
      sys_munmap(mapid);
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
    sys_exit(-1);
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
sys_halt(void)
{
  power_off();
}

static void
sys_exit(int status)
{
  if(lock_held_by_current_thread(&file_lock))
      lock_release(&file_lock);
  thread_current()->exit_status = status;
  thread_exit();
}

static pid_t
sys_exec(const char *cmd_line)
{
  pid_t pid;

  if(is_valid(cmd_line)){
    pid = process_execute(cmd_line);
    return pid;
  }
  else
    sys_exit(-1);
}

static int
sys_wait(pid_t pid)
{
  return process_wait(pid);
}

static bool
sys_create(const char *file, unsigned initial_size)
{
  bool create;

  if(is_valid(file)){
    lock_acquire(&file_lock);
    create = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return create;
  }
  else
    sys_exit(-1);
}

static bool
sys_remove(const char *file)
{
  bool remove;

  if(is_valid(file)){
    lock_acquire(&file_lock);
    remove = filesys_remove(file);
    lock_release(&file_lock);
    return remove;
  }
  else
    sys_exit(-1);
}

static int
sys_open(const char *file)
{
  if(is_valid(file)){
    int fd;
    struct thread *t = thread_current();
    struct thread_filesys *tf = malloc(sizeof(struct thread_filesys));

    lock_acquire(&file_lock);
    struct file *of = filesys_open(file);
    lock_release(&file_lock);

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
    return fd;
  }
  else
    sys_exit(-1);
}

static int
sys_filesize(int fd)
{
  int size;
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf){
    lock_acquire(&file_lock);
    size = file_length(tf->file);
    lock_release(&file_lock);
  }
  else
    size = 0;
  return size;
}

static int
sys_read(int fd, void *buffer, unsigned size)
{
  int result;

  if(is_valid(buffer)){
    if(fd == 0)
      input_getc();
    else{
      struct thread *t = thread_current();
      struct thread_filesys *tf = lookup_fd(t, fd);
      if(tf){
        lock_acquire(&file_lock);
        result = file_read(tf->file, buffer, size);
        lock_release(&file_lock);
      }
      else
        result = -1;
      return result;
    }
  }
  else
    sys_exit(-1);
}

static int
sys_write(int fd, const void *buffer, unsigned size)
{
  int result;

  if(is_valid(buffer)){
    if(fd == 1)
      putbuf(buffer, size);
    else{
      struct thread *t = thread_current();
      struct thread_filesys *tf = lookup_fd(t, fd);
      if(tf){
        lock_acquire(&file_lock);
        result = file_write(tf->file, buffer, size);
        lock_release(&file_lock);
      }
      else
        result = -1;
      return result;
    }
  }
  else
    sys_exit(-1);
}

static void
sys_seek(int fd, unsigned position)
{
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf){
    lock_acquire(&file_lock);
    file_seek(tf->file, position);
    lock_release(&file_lock);
  }
}

static unsigned
sys_tell(int fd)
{
  unsigned result;
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf){
    lock_acquire(&file_lock);
    result = file_tell(fd);
    lock_release(&file_lock);
  }
  else
    result = -1;
  return result;
}

static void
sys_close(int fd)
{
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf){
    lock_acquire(&file_lock);
    file_close(tf->file);
    lock_release(&file_lock);
    list_remove(&tf->elem);
    free(tf);
  }
}

static mapid_t
sys_mmap(int fd, void *addr)
{
  void *i;
  int ofs = 0, filesize = sys_filesize(fd);

  if(fd == 0 || fd == 1 || addr == NULL || pg_ofs(addr) || filesize == 0)
    return -1;

  for(i = addr; i < addr + filesize; i += PGSIZE)
    if(spt_find(addr) != NULL) return -1;

  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  struct thread_mmap *tm = (struct thread_mmap *)malloc(sizeof(struct thread_mmap));
  tm->mapid = t->max_mapid++;
  lock_acquire(&file_lock);
  tm->file = file_reopen(tf->file);
  lock_release(&file_lock);
  tm->start_addr = addr;
  tm->size = filesize;
  list_push_back(&t->mmaps, &tm->elem);

//  frame_lock_ac();
  while(filesize > 0){
    struct spte *pseudo_spte = spte_create(addr + ofs, NULL, P_MMAP | P_LAZY | P_WRITABLE);
    pseudo_spte->file = tm->file;
    pseudo_spte->ofs = ofs;
    pseudo_spte->read_bytes = filesize < PGSIZE ? filesize : PGSIZE;
    ofs += PGSIZE;
    filesize -= PGSIZE;
  }
//  frame_lock_rl();

  return tm->mapid;
}

static void
sys_munmap(mapid_t mapid)
{
  struct thread *t = thread_current();
  struct thread_mmap *tm = lookup_mapid(t, mapid);
  if(tm){
    frame_lock_ac();
    mmap_free(tm);
    frame_lock_rl();
    list_remove(&tm->elem);
    free(tm);
  }
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
  /* not found. */
  return NULL;
}

static struct thread_mmap
*lookup_mapid(struct thread *t, mapid_t mapid)
{
  struct list_elem *e;
  for(e = list_begin(&t->mmaps); e != list_end(&t->mmaps); e = list_next(e)){
    struct thread_mmap *tm = list_entry(e, struct thread_mmap, elem);
    if(tm->mapid == mapid)
      return tm;
  }
  return NULL;
}

void
mmap_free(struct thread_mmap *tm)
{
  ASSERT(frame_lock_held_by_curr());
  struct spte *p;
  int status;
  bool dirty;
  void *addr = tm->start_addr;
  int size = tm->size;
  struct thread *t = thread_current();

  while(size > 0){
    p = spt_find(addr);
    ASSERT(p != NULL);
    ASSERT(p->status & P_MMAP);
    ASSERT(t == p->thread);

    status = p->status;
    dirty = pagedir_is_dirty(t->pagedir, addr);

    if(!(status & P_LAZY) && !(status & P_INSWAP)){
      struct frame_entry *f = p->frame_entry;
      ASSERT(f != NULL);
      if(dirty) file_out(p);
      frame_free(f);
    }
    spte_free(p);
    addr += PGSIZE;
    size -= PGSIZE;
  }
  lock_acquire(&file_lock);
  file_close(tm->file);
  lock_release(&file_lock);
}

void
file_out(struct spte *spte)
{
  ASSERT(frame_lock_held_by_curr());
  ASSERT(spte->frame_entry != NULL);

  lock_acquire(&file_lock);
  file_seek(spte->file, spte->ofs);
  file_write(spte->file, spte->frame_entry->frame_addr, spte->read_bytes);
  lock_release(&file_lock);
}

void
file_in(struct spte *spte, struct frame_entry *f)
{
  ASSERT(frame_lock_held_by_curr());

  lock_acquire(&file_lock);
  file_seek(spte->file, spte->ofs);
  file_read(spte->file, f->frame_addr, spte->read_bytes);
  lock_release(&file_lock);
}
