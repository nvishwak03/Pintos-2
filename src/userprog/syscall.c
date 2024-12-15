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

static struct semaphore filesys_sema;

static int fd = 2;
struct open_file
{
  int fd;
  struct file* f;
  struct list_elem elem;
};

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  sema_init(&filesys_sema, 1);
}

static bool verify_user (const void *uaddr) {
  bool phys_base = (uaddr < PHYS_BASE);
  void *page = NULL;
  if (phys_base) {
    page = pagedir_get_page(thread_current()->pagedir, uaddr);
  }
  bool is_mapped = (page != NULL);
  return phys_base && is_mapped;
}

static inline bool get_user (uint8_t *dst, const uint8_t *usrc) {
  int eax;
  uint8_t value = 0;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (value), "=&a" (eax) : "m" (*usrc));
  *dst = value;
  bool success = (eax != 0);
  return success;
}
 
static inline bool put_user (uint8_t *udst, uint8_t byte) {
  int eax;
  uint8_t value = byte;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (value));
  bool success = (eax != 0);
  return success;
}

static bool access_user_data 
(void *dst, const void *src, size_t size, enum user_access_type uat) 
{
  uint8_t *dst_byte = (uint8_t *)dst;
  uint8_t *src_byte = (uint8_t *)src;
  size_t i = 0;
  while (i < size) 
  {
    if (uat == USER_READ) 
    {
      if (!(verify_user(src_byte + i) && get_user(dst_byte + i, src_byte + i)))
        return false;
    } 
    else if (uat == USER_WRITE) 
    {
      if (!(verify_user(dst_byte + i) && put_user(dst_byte + i, *(src_byte + i))))
        return false;
    } 
    else 
    {
      return false;
    }
    i++;
  }
  return true;
}


static bool verify_string(const char* s)
{
  int i = 0;
  while (verify_user(s + i))
  {
    if (s[i] != '\0')
      i++;
    else
      return true;
  }
  return false;
}

static struct open_file* get_open_file (int target_fd)
{
  struct list *fd_list = &thread_current()->files;
  struct list_elem *current_elem = list_begin(fd_list);

  while (current_elem != list_end(fd_list))
  {
    struct open_file *opfile_entry = list_entry(current_elem, struct open_file, elem);
    return (opfile_entry->fd == target_fd) ? opfile_entry : (current_elem = list_next(current_elem), NULL);
  }

  return NULL;
}

void close_files(void) {
    struct list *fd_list = &thread_current()->files;
    while (!list_empty(fd_list)) {
        struct list_elem *elem = list_pop_front(fd_list);
        struct open_file *opfile_entry = list_entry(elem, struct open_file, elem);
        
        sema_down(&filesys_sema);
        file_close(opfile_entry->f);
        sema_up(&filesys_sema);

        free(opfile_entry);
    }
}

void notify_exit(void) {
    struct list *ch_list = &thread_current()->child;
    while (!list_empty(ch_list)) {
        struct list_elem *elem = list_pop_front(ch_list);
        struct process *ch_process = list_entry(elem, struct process, elem);
        ch_process->par_status = false;
    }
}

void handle_parent(void) {
    struct process *c_process = thread_current()->p;
    if (c_process->par_status) {
        sema_up(&c_process->semaExit);
    } 
}

int sys_exit(int exit_code, int arg1 UNUSED, int arg2 UNUSED) {
    struct thread *c_thread = thread_current();
    struct process *c_process = c_thread->p;
    c_process->status_exit = exit_code;
    printf("%s: exit(%d)\n", c_thread->name, exit_code);
    close_files();
    notify_exit();
    file_close(c_process->f);
    handle_parent();
    thread_exit();
}

static int handle_invalid_buffer(const void *buffer) {
    return (buffer == NULL || !verify_user(buffer)) ? (sys_exit(-1, 0, 0), 0) : 1;
}

static int write_to_stdout(const void *buffer, unsigned length) {
    putbuf(buffer, length);
    return length;
}

static struct open_file* get_open_file_checked(int fd) {
    return get_open_file(fd);
}

static int write_to_file(struct open_file *of, const void *buffer, unsigned length) {
    char *kernel_buffer = malloc(length);
    return (!access_user_data(kernel_buffer, buffer, length, USER_READ))
        ? (free(kernel_buffer), sys_exit(-1, 0, 0), 0)
        : ({
            sema_down(&filesys_sema);
            int bytes_written = file_write(of->f, kernel_buffer, length);
            sema_up(&filesys_sema);
            free(kernel_buffer);
            bytes_written;
        });
}

static int sys_write(int arg0, int arg1, int arg2) {
    int fd = arg0;
    const void *buffer = (const void *)arg1;
    unsigned length = (unsigned)arg2;

    return handle_invalid_buffer(buffer) && fd == 1
        ? write_to_stdout(buffer, length)
        : ({
            struct open_file *of = get_open_file_checked(fd);
            of ? write_to_file(of, buffer, length) : -1;
        });
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

static int sys_create(int arg0, int arg1, int arg2 UNUSED) 
{ 
  const char *str = (const char *)arg0;
  unsigned size = (unsigned)arg1;
  sema_down(&filesys_sema);
  bool result = (str == NULL || !verify_string(str)) ? (sys_exit(-1, 0, 0), false) : filesys_create(str, size);
  sema_up(&filesys_sema);

  return result; 
}

static int sys_remove(int arg0, int arg1 UNUSED, int arg2 UNUSED) 
{ 
  const char *str = (const char *)arg0;
  sema_down(&filesys_sema);
  bool result = (str == NULL || !verify_string(str)) ? (sys_exit(-1, 0, 0), false) : filesys_remove(str);
  sema_up(&filesys_sema);

  return result; 
}


static struct file* get_file_to_open(const char *filename) 
{
    if (filename == NULL || !verify_string(filename))
        sys_exit(-1, 0, 0);
    sema_down(&filesys_sema);
    struct file *opened_file = filesys_open(filename);
    sema_up(&filesys_sema);

    return opened_file;
}

static int sys_open(int filename_ptr, int unused1 UNUSED, int unused2 UNUSED) 
{
    const char *filename = (const char *)filename_ptr;
    struct file *f_open = get_file_to_open(filename);
    if (f_open == NULL)
        return -1;
    struct open_file *opfile_entry = malloc(sizeof(struct open_file));
    opfile_entry->f = f_open;
    opfile_entry->fd = fd++;
    list_push_back(&thread_current()->files, &opfile_entry->elem);

    return opfile_entry->fd;
}


static int sys_filesize(int arg0, int arg1 UNUSED, int arg2 UNUSED)
{
    int file_descriptor = arg0;
    struct open_file *opfile_struct = get_open_file(file_descriptor);
    if (opfile_struct == NULL)
    {
        return 0;
    }
    int computed_file_size = file_length(opfile_struct->f);
    return computed_file_size;
}

static bool is_valid(void *user_buffer)
{
    return user_buffer != NULL && verify_user(user_buffer);
}

static int read_char(void *user_buffer)
{
    char input_char = input_getc();
    int num_bytes_read = 1;
    return access_user_data(user_buffer, &input_char, num_bytes_read, USER_WRITE) ? num_bytes_read : -1;
}

static int read_data(struct open_file *file_handle, void *user_buffer, unsigned read_length)
{
    if (read_length == 0) 
        return 0;
    char *temp_kernel_buffer = malloc(read_length);
    if (temp_kernel_buffer == NULL)
        return -1;
    sema_down(&filesys_sema);
    int num_bytes_read = file_read(file_handle->f, temp_kernel_buffer, read_length);
    sema_up(&filesys_sema);
    bool write_successful = access_user_data(user_buffer, temp_kernel_buffer, num_bytes_read, USER_WRITE);
    free(temp_kernel_buffer);

    return write_successful ? num_bytes_read : -1;
}

static int sys_read(int file_descriptor, int user_buffer_address, int read_length)
{
    int fd_read = file_descriptor;
    void *user_buffer = (void *)user_buffer_address;
    unsigned num_read = (unsigned)read_length;
    if (num_read == 0)
        return 0;
    if (!is_valid(user_buffer))
        sys_exit(-1, 0, 0);

    int total_bytes_read = 0;
    switch (fd_read)
    {
        case 0: 
            total_bytes_read = read_char(user_buffer);
            break;
        default: 
        {
            struct open_file *fp = get_open_file(fd_read);
            total_bytes_read = (fp != NULL)
                ? read_data(fp, user_buffer, num_read)
                : -1;
            break;
        }
    }
    return (total_bytes_read < 0) ? (sys_exit(-1, 0, 0), 0) : total_bytes_read;
}

static int sys_seek(int arg0, int arg1, int arg2 UNUSED)
{ 
    int f_identifier = arg0;                     
    unsigned tar_position = (unsigned)arg1;     
    struct open_file *opfile_entry = get_open_file(f_identifier); 

    if (!opfile_entry || !opfile_entry->f) {
        sys_exit(-1, 0, 0); 
    }

    file_seek(opfile_entry->f, tar_position); 
    return 0; 
}

static int sys_tell(int arg0, int arg1 UNUSED, int arg2 UNUSED)
{ 
    int f_identifier = arg0;                 
    struct open_file *opfile_entry = get_open_file(f_identifier); 
    if (!opfile_entry || !opfile_entry->f) {
        sys_exit(-1, 0, 0); 
    }

    return file_tell(opfile_entry->f); 
}


static int sys_close(int arg0, int arg1 UNUSED, int arg2 UNUSED)
{ 
    int f_descriptor = arg0;                     
    struct open_file *opfile_entry = get_open_file(f_descriptor); 

    opfile_entry 
        ? (list_remove(&opfile_entry->elem), free(opfile_entry)) 
        : (void)0; 

    return 0; 
}

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

static void syscall_handler(struct intr_frame *f)
{
    int a = 0;              
    int b[3] = {0, 0, 0};    

    void *c = f->esp;       
    if (!access_user_data(&a, c, 4, USER_READ))
    {
        sys_exit(-1, 0, 0);  
    }
    struct syscall *d = &syscall_array[a];
    int e = d->argc;
    switch (e)
    {
        case 3:
        {
            void *f = c + 12;  
            if (!access_user_data(&b[2], f, 4, USER_READ))
            {
                sys_exit(-1, 0, 0);  
            }
            __attribute__((fallthrough));
        }
        case 2:
        {
            void *g = c + 8;  
            if (!access_user_data(&b[1], g, 4, USER_READ))
            {
                sys_exit(-1, 0, 0);  
            }
            __attribute__((fallthrough));
        }
        case 1:
        {
            void *h = c + 4;   
            if (!access_user_data(&b[0], h, 4, USER_READ))
            {
                sys_exit(-1, 0, 0);  
            }
            break;
        }
        default:
            break;
    }
    int i = d->func(b[0], b[1], b[2]);
    f->eax = i;  
    return;
}