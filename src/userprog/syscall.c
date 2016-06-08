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
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

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
static bool sys_chdir(const char *);
static bool sys_mkdir(const char *);
static bool sys_readdir(int, char *);
static bool sys_isdir(int);
static int sys_inumber(int);
static mapid_t sys_mmap(int, void *);
static void sys_munmap(mapid_t);
static struct thread_filesys *lookup_fd(struct thread *, int);
static struct thread_mmap *lookup_mapid(struct thread *, mapid_t);

void
syscall_init (void)
{
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

    case SYS_CHDIR:
      bad_esp_filter(f, 1);
      file = nth_arg(f, 1);
      f->eax = sys_chdir(file);
      break;

    case SYS_MKDIR:
      bad_esp_filter(f, 1);
      file = nth_arg(f, 1);
      f->eax = sys_mkdir(file);
      break;

    case SYS_READDIR:
      bad_esp_filter(f, 2);
      fd = nth_arg(f, 1);
      buffer = nth_arg(f, 2);
      f->eax = sys_readdir(fd, buffer);
      break;

    case SYS_ISDIR:
      bad_esp_filter(f, 1);
      fd = nth_arg(f, 1);
      f->eax = sys_isdir(fd);
      break;

    case SYS_INUMBER:
      bad_esp_filter(f, 1);
      fd = nth_arg(f, 1);
      f->eax = sys_inumber(fd);
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
    create = filesys_create(file, initial_size);
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
    remove = filesys_remove(file);
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

    struct file *of = filesys_open(file);

    if(of){
      fd = t->maxfd + 1;
      t->maxfd = fd;
      tf->fd = fd;
      tf->file = of;
      tf->is_dir = file_get_inode(tf->file)->is_dir;
      if(tf->is_dir) {
        tf->dir = dir_open(inode_reopen(file_get_inode(tf->file)));
      }
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
    if(tf->is_dir) return -1;
    size = file_length(tf->file);
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
        if(tf->is_dir) return -1;
        result = file_read(tf->file, buffer, size);
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
        if(tf->is_dir) return -1;
        result = file_write(tf->file, buffer, size);
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
    if(tf->is_dir) return -1;
    file_seek(tf->file, position);
  }
}

  static unsigned
sys_tell(int fd)
{
  unsigned result;
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf){
    if(tf->is_dir) return -1;
    result = file_tell(tf->file);
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
    if(tf->is_dir) free(tf->dir);
    file_close(tf->file);
    list_remove(&tf->elem);
    free(tf);
  }
}

  static bool
sys_chdir(const char *dir)
{
  return change_dir(dir);
}

  static bool
sys_mkdir(const char *dir)
{
  return make_dir(dir);
}

static bool
sys_readdir(int fd, char *buffer)
{
  if(is_valid(buffer)){
    struct thread *t = thread_current();
    struct thread_filesys *tf = lookup_fd(t, fd);
    if(tf){
      if(!tf->is_dir) return false;
      return read_dir(tf->dir, buffer);
    }
    else return false;
  }
  else return false;
}

static bool
sys_isdir(int fd)
{
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf){
    return tf->is_dir;
  }
  else return false;
}

static int
sys_inumber(int fd)
{
  struct thread *t = thread_current();
  struct thread_filesys *tf = lookup_fd(t, fd);
  if(tf){
    return (file_get_inode(tf->file))->sector;
  }
  else return -1;
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
  tm->file = file_reopen(tf->file);
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
  file_close(tm->file);
}

void
file_out(struct spte *spte)
{
  ASSERT(frame_lock_held_by_curr());
  ASSERT(spte->frame_entry != NULL);

  file_write_at(spte->file, spte->frame_entry->frame_addr, spte->read_bytes, spte->ofs);
}

void
file_in(struct spte *spte, struct frame_entry *f)
{
  ASSERT(frame_lock_held_by_curr());

  file_read_at(spte->file, f->frame_addr, spte->read_bytes, spte->ofs);
}
