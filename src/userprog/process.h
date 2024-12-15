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
    struct list args;
    struct file *f;
    char *name;
    tid_t tid;
    struct semaphore semaLoad;
    struct semaphore semaExit;
    struct list_elem elem;
    bool par_status;
    int status_load;
    int status_exit;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */