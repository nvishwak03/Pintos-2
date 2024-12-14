#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

enum user_access_type
{
  USER_READ, USER_WRITE
};

// Lock required for making calls into filesys. Concurrency
// is not supported for those calls
static struct lock filesys_lock;

// TODO: this is just going to keep increasing, which would ultimately
// break on integer overflow, though that probably won't happen
static int fd = 2;
struct open_file
{
  int fd;
  struct file* f;
  struct list_elem elem;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}


// User memory access functions

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool verify_user (const void *uaddr) {
  return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}
 
/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool get_user (uint8_t *dst, const uint8_t *usrc) {
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool put_user (uint8_t *udst, uint8_t byte) {
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}

// wrapper around user memory access functions
// reads or writes SIZE number of bytes from/to user space
// DST and SRC are used with respect to UAT
static bool access_user_data 
(void *dst, const void *src, size_t size, enum user_access_type uat) 
{
  uint8_t *dst_byte = (uint8_t *)dst;
  uint8_t *src_byte = (uint8_t *)src;

  for (unsigned i=0; i < size; i++)
  {
    switch (uat){
      case USER_READ:
        if(!(verify_user(src_byte+i) && get_user(dst_byte+i, src_byte+i)))
          return false;
        break;

      case USER_WRITE:
        if(!(verify_user(dst_byte+i) && put_user(dst_byte+i, *(src_byte+i))))
          return false;
        break;
      
      default:
        return false;
    }
  }
  return true;
}

// verifies that all bytes of a string pointed
// to by S are in valid user address space
static bool verify_string(const char* s)
{
  for(int i = 0; verify_user(s+i); i++)
  {
    if(s[i] == '\0')
      return true;
  }
  return false;
}

// System calls

// get an open_file if it's in the thread's fd list
// else, return 0
static struct open_file* get_open_file (int fd)
{
  struct list *file_descriptors = &thread_current()->file_descriptors;
  struct list_elem *e;
  for (e = list_begin (file_descriptors); e != list_end (file_descriptors);
        e = list_next (e))
    {
      struct open_file *of = list_entry (e, struct open_file, elem);
      if(of->fd == fd)
        return of;
    }
  return NULL;
}

int sys_exit (int arg0, int arg1 UNUSED, int arg2 UNUSED)
{
  int status = arg0;

  thread_current()->p->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);

  // when running with USERPROG defined, thread_exit will also call process_exit 
  if(lock_held_by_current_thread(&filesys_lock))
    lock_release(&filesys_lock);
  
  // Free open files
  struct list *file_descriptors = &thread_current()->file_descriptors;
  while (!list_empty (file_descriptors))
  {
    struct list_elem *e = list_pop_front (file_descriptors);
    struct open_file *of = list_entry (e, struct open_file, elem);
    lock_acquire(&filesys_lock);
    file_close(of->f);
    lock_release(&filesys_lock);
    free(of);
  }

  // Inform children that parent has exited
  struct list *active_child_processes = &thread_current()->active_child_processes;
  while (!list_empty (active_child_processes))
  {
    struct list_elem *e = list_pop_front (active_child_processes);
    struct process *p = list_entry (e, struct process, elem);
    p->parent_alive = false;
  }

  file_close (thread_current()->p->f);

  bool parent_alive = thread_current()->p->parent_alive;
  if(parent_alive)
    sema_up(&(thread_current()->p->on_exit));
  else 
    free(thread_current()->p);

  thread_exit();
}

static int sys_write (int arg0, int arg1, int arg2)
{
  int fd = arg0;
  const void *buffer = (const void*)arg1;
  unsigned length = (unsigned)arg2;
  int bytes_written = 0;
  char *kernel_buffer;

  if(buffer == NULL || !verify_user(buffer))
    sys_exit(-1, 0, 0);

  // writing to stdout
  if(fd == 1)
  {
    putbuf(buffer, length);
    bytes_written = length;
  }
  else
  {
    struct open_file *of = get_open_file(fd);
    if(!of)
      return -1;

    kernel_buffer = malloc(length);
    if(!access_user_data(kernel_buffer, buffer, length, USER_READ))
    {
      free(kernel_buffer);
      sys_exit(-1, 0, 0);
    }
    lock_acquire(&filesys_lock);
    bytes_written = file_write(of->f, kernel_buffer, length);
    lock_release(&filesys_lock);
  }

  return bytes_written;
}

static int sys_halt(int arg0 UNUSED, int arg1 UNUSED, int arg2 UNUSED)
{
  shutdown_power_off();
}

static int sys_exec (int arg0, int arg1 UNUSED, int arg2 UNUSED)
{ 
  const char *args = (const char*)arg0;

  if(!verify_string(args))
    sys_exit(-1, 0, 0);
  
  return process_execute(args);
}

static int sys_wait (int arg0, int arg1 UNUSED, int arg2 UNUSED)
{ 
  pid_t pid = arg0;

  return process_wait(pid); 
}

static int sys_create (int arg0, int arg1, int arg2 UNUSED)
{ 
  const char *file = (const char*)arg0;
  unsigned initial_size = (unsigned)arg1;
  bool success = false;

  if(file == NULL || !verify_string(file))
    sys_exit(-1, 0, 0);

  lock_acquire(&filesys_lock);
  success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);

  return success; 
}

static int sys_remove (int arg0, int arg1 UNUSED, int arg2 UNUSED)
{ 
  const char *file = (const char *)arg0;
  bool success = false;
  
  if(file == NULL || !verify_string(file))
    sys_exit(-1, 0, 0);

  lock_acquire(&filesys_lock);
  success = filesys_remove(file);
  lock_release(&filesys_lock);

  return success; 
  return 0;
}

static int sys_open (int arg0, int arg1 UNUSED, int arg2 UNUSED)
{ 
  const char *file = (const char *)arg0;

  if(file == NULL || !verify_string(file))
    sys_exit(-1, 0, 0);

  struct file *f;
  lock_acquire(&filesys_lock);
  if(!(f = filesys_open(file)))
    return -1;
  lock_release(&filesys_lock);

  struct open_file *of = malloc(sizeof(struct open_file));
  of->f = f;
  of->fd = fd++;
  list_push_back(&thread_current()->file_descriptors, &of->elem);

  return of->fd; 
}

static int sys_filesize (int arg0, int arg1 UNUSED, int arg2 UNUSED)
{ 
  int fd = arg0;
  struct open_file *of = get_open_file(fd);
  if(!of)
    return 0;
  return file_length(of->f);
}

static int sys_read (int arg0, int arg1, int arg2)
{ 
  int fd = arg0;
  void *buffer = (void*)arg1;
  unsigned length = (unsigned)arg2;
  char *kernel_buffer;
  int bytes_read = 0;

  if(buffer == NULL || !verify_user(buffer))
    sys_exit(-1, 0, 0);
  
  if(fd == 0)
  {
    char c = input_getc();
    bytes_read = 1;
    if(!access_user_data(buffer, &c, bytes_read, USER_WRITE))
      sys_exit(-1, 0, 0);
  }
  else
  {
    struct open_file *of = get_open_file(fd);
    if(!of)
      return -1;

    kernel_buffer = malloc(length);
    lock_acquire(&filesys_lock);
    bytes_read = file_read(of->f, kernel_buffer, length);
    lock_release(&filesys_lock);

    if(!access_user_data(buffer, kernel_buffer, bytes_read, USER_WRITE))
    {
      free(kernel_buffer);
      sys_exit(-1, 0, 0);
    }
    free(kernel_buffer);
  }
  
  return bytes_read; 
}

static int sys_seek (int arg0, int arg1, int arg2 UNUSED)
{ 
  int fd = arg0;
  unsigned position = (unsigned)arg1;
  struct open_file *of = get_open_file(fd);

  file_seek(of->f, position);
  return 0; 
}

static int sys_tell (int arg0, int arg1 UNUSED, int arg2 UNUSED)
{ 
  int fd = arg0;
  struct open_file *of = get_open_file(fd);

  file_tell(of->f);
  
  return 0; 
}

static int sys_close (int arg0, int arg1 UNUSED, int arg2 UNUSED)
{ 
  int fd = arg0;
  struct open_file *of = get_open_file(fd);

  if(of)
  {
    list_remove(&of->elem);
    free(of);
  }

  return 0;
}

// Syscall dispatch table
typedef int syscall_func(int, int, int);
struct syscall
{
  int argc;
  syscall_func *func;
};

static struct syscall syscall_array[] =
{
  {0, sys_halt}, {1, sys_exit}, {1, sys_exec}, {1, sys_wait},
  {2, sys_create}, {1, sys_remove}, {1, sys_open}, {1, sys_filesize},
  {3, sys_read}, {3, sys_write}, {2, sys_seek}, {1, sys_tell}, {1, sys_close}
};

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_number = 0;
  int args[3] = {0,0,0};

  if(!access_user_data(&syscall_number, f->esp, 4, USER_READ))
    sys_exit(-1, 0, 0);

  // fallthrough here is intentional
  struct syscall *sc = &syscall_array[syscall_number];
  switch(sc->argc)
  {
    case 3:
      if(!access_user_data(&args[2], f->esp+12, 4, USER_READ))
        sys_exit(-1, 0, 0);
      __attribute__((fallthrough));

    case 2:
      if(!access_user_data(&args[1], f->esp+8, 4, USER_READ))
        sys_exit(-1, 0, 0);
      __attribute__((fallthrough));

    case 1:
      if(!access_user_data(&args[0], f->esp+4, 4, USER_READ))
        sys_exit(-1, 0, 0);
  }
  f->eax = sc->func(args[0], args[1], args[2]);
  return;
}