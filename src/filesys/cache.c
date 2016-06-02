#include <list.h>
#include <string.h>
#include "threads/synch.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"

struct lock cache_lock;
struct list caches; /* MLU cache on the left side of the queue */
int cache_cnt;

struct cache_entry
  {
    disk_sector_t sector;
    bool dirty;
    char data[512];
    struct list_elem elem;
  };

static struct cache_entry *cache_find(disk_sector_t);
static struct cache_entry *cache_in(disk_sector_t);
static void cache_read(struct cache_entry *, void *);
static void cache_write(struct cache_entry *, const void *);

void
cache_init(void)
{
  lock_init(&cache_lock);
  list_init(&caches);
  cache_cnt = 0;
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

static struct cache_entry *
cache_in(disk_sector_t sec_no)
{
  struct cache_entry *c;
  if(cache_cnt == 64){
    /* eviction routine */
    struct list_elem *e = list_pop_back(&caches);
    c = list_entry(e, struct cache_entry, elem);
    if(c->dirty)
      disk_write(filesys_disk, c->sector, &c->data);
  }
  else{
    c = (struct cache_entry *)malloc(sizeof(struct cache_entry));
    cache_cnt++;
  }
  c->sector = sec_no;
  disk_read(filesys_disk, sec_no, &c->data);
  c->dirty = false;
  list_push_front(&caches, &c->elem);
  return c;
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
void
disk_read_with_cache(disk_sector_t sec_no, void *buffer)
{
  lock_acquire(&cache_lock);
  struct cache_entry *c = cache_find(sec_no);
  if(c){
    list_remove(&c->elem);
    cache_read(c, buffer);
    list_push_front(&caches, &c->elem);
    lock_release(&cache_lock);
    return;
  }
  else{
    c = cache_in(sec_no);
    cache_read(c, buffer);
    lock_release(&cache_lock);
    return;
  }
}

void
disk_write_with_cache(disk_sector_t sec_no, const void *buffer)
{
  lock_acquire(&cache_lock);
  struct cache_entry *c = cache_find(sec_no);
  if(c){
    list_remove(&c->elem);
    cache_write(c, buffer);
    list_push_front(&caches, &c->elem);
    lock_release(&cache_lock);
  }
  else{
    c = cache_in(sec_no);
    cache_write(c, buffer);
    lock_release(&cache_lock);
    return;
  }
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
