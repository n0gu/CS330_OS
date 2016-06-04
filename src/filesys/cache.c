#include <list.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"

#define MAX_CACHE 64
#define MAX_REQUEST 32

struct list caches; /* MLU cache on the left side of the queue */
struct lock cache_lock;
int cache_cnt;

struct list requests; /* read-ahead requests */
struct lock request_lock;
struct semaphore req_ready;
int req_cnt;

struct cache_entry
  {
    struct lock entry_lock;
    disk_sector_t sector;
    bool dirty;
    char data[512];
    struct list_elem elem;
  };

struct request_entry
  {
    disk_sector_t sector;
    struct list_elem elem;
  };

static struct cache_entry *cache_find(disk_sector_t);
static void disk_io_helper(disk_sector_t, void *, bool);
static void cache_read(struct cache_entry *, void *);
static void cache_write(struct cache_entry *, const void *);

static struct request_entry *req_pop_front(void);
static void read_ahead_handler(void);
static void read_ahead(struct request_entry *);

void
cache_init(void)
{
  list_init(&caches);
  lock_init(&cache_lock);
  cache_cnt = 0;

  list_init(&requests);
  lock_init(&request_lock);
  sema_init(&req_ready, 0);
  req_cnt = 0;

  thread_create("Read-ahead", PRI_DEFAULT, read_ahead_handler, NULL);
}

static struct cache_entry *
cache_find(disk_sector_t sec_no)
{
  struct list_elem *e;

  for(e = list_begin(&caches); e != list_end(&caches); e = list_next(e)){
    struct cache_entry *c = list_entry(e, struct cache_entry, elem);
    if(c->sector == sec_no)
      return c;
  }
  return NULL;
}

static void
cache_read(struct cache_entry *cache, void *buffer)
{
  memcpy(buffer, &cache->data, 512);
}

static void
cache_write(struct cache_entry *cache, const void *buffer)
{
  memcpy(&cache->data, buffer, 512);
  cache->dirty = true;
}

/* filesys read & write wrapper with synchronization */
static void
disk_io_helper(disk_sector_t sec_no, void *buffer, bool read)
{
  lock_acquire(&cache_lock);
  struct cache_entry *c = cache_find(sec_no);
  if(c){
    list_remove(&c->elem);
    list_push_front(&caches, &c->elem);
    lock_acquire(&c->entry_lock);
    lock_release(&cache_lock);
  }
  else{
    if(cache_cnt == MAX_CACHE){
      c = list_entry(list_pop_back(&caches), struct cache_entry, elem);
      list_push_front(&caches, &c->elem);
      lock_acquire(&c->entry_lock);
      disk_sector_t old_sector = c->sector;
      c->sector = sec_no;
      lock_release(&cache_lock);
      if(c->dirty)
        disk_write(filesys_disk, old_sector, &c->data);
    }
    else{
      c = (struct cache_entry *)malloc(sizeof(struct cache_entry));
      list_push_front(&caches, &c->elem);
      cache_cnt++;
      lock_init(&c->entry_lock);
      lock_acquire(&c->entry_lock);
      c->sector = sec_no;
      lock_release(&cache_lock);
    }
    c->dirty = false;
    disk_read(filesys_disk, c->sector, &c->data);
  }
  if(read)
    cache_read(c, buffer);
  else
    cache_write(c, buffer);
  lock_release(&c->entry_lock);
}

void
disk_read_with_cache(disk_sector_t sec_no, void *buffer)
{
  disk_io_helper(sec_no, buffer, true);
}

void
disk_write_with_cache(disk_sector_t sec_no, const void *buffer)
{
  disk_io_helper(sec_no, buffer, false);
}

void
flush_cache(void)
{
  lock_acquire(&cache_lock);
  while(!list_empty(&caches)){
    struct list_elem *e = list_pop_front(&caches);
    struct cache_entry *c = list_entry(e, struct cache_entry, elem);
    if(c->dirty)
      disk_write(filesys_disk, c->sector, &c->data);
    free(c);
  }
  lock_release(&cache_lock);
}


void
send_request(disk_sector_t sec_no)
{
// printf("sending reques to %d\n", sec_no);
  struct request_entry *r;
  struct list_elem *e;
  lock_acquire(&request_lock);
  for(e = list_begin(&requests); e != list_end(&requests); e = list_next(e)){
    r = list_entry(e, struct request_entry, elem);
    if(r->sector == sec_no){
      lock_release(&request_lock);
      return;
    }
  }
  r = (struct request_entry *)malloc(sizeof(struct request_entry));
  r->sector = sec_no;
  list_push_back(&requests, &r->elem);
  if(++req_cnt == 1)
    sema_up(&req_ready);
  lock_release(&request_lock);
}

static struct request_entry *
req_pop_front(void)
{
  lock_acquire(&request_lock);
  if(req_cnt == 0){
    lock_release(&request_lock);
    return NULL;
  }
  struct list_elem *e = list_pop_front(&requests);
  struct request_entry *r = list_entry(e, struct request_entry, elem);
  req_cnt--;
  lock_release(&request_lock);
  return r;
}

static void
read_ahead_handler(void)
{
  struct request_entry *r;
  work:
  while(r = req_pop_front())
    read_ahead(r);
  sema_down(&req_ready);
  goto work;
}

static void
read_ahead(struct request_entry *r)
{
  disk_sector_t sec_no = r->sector;
  lock_acquire(&cache_lock);
//  printf("reading ahead %d, current length %d\n", sec_no, req_cnt);
  struct cache_entry *c = cache_find(sec_no);
  if(c){
    lock_release(&cache_lock);
  }
  else{
    if(cache_cnt == MAX_CACHE){
      c = list_entry(list_pop_back(&caches), struct cache_entry, elem);
      list_push_front(&caches, &c->elem);
      lock_acquire(&c->entry_lock);
      disk_sector_t old_sector = c->sector;
      c->sector = sec_no;
      lock_release(&cache_lock);
      if(c->dirty)
        disk_write(filesys_disk, old_sector, &c->data);
    }
    else{
      c = (struct cache_entry *)malloc(sizeof(struct cache_entry));
      list_push_front(&caches, &c->elem);
      cache_cnt++;
      lock_init(&c->entry_lock);
      lock_acquire(&c->entry_lock);
      c->sector = sec_no;
      lock_release(&cache_lock);
    }
    c->dirty = false;
    disk_read(filesys_disk, c->sector, &c->data);
    lock_release(&c->entry_lock);
  }
  free(r);
}
