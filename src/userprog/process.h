#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

struct arg
{
  char *value;
  struct list_elem elem;
};

struct process
{
    struct file *f;
    char *name;
    struct list args;
    tid_t tid;
    bool parent_alive;
    struct semaphore on_load;
    int load_success;
    struct semaphore on_exit;
    int exit_status;
    struct list_elem elem;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */