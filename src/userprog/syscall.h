#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

void syscall_init (void);
int sys_exit(int, int, int);

#endif /* userprog/syscall.h */
