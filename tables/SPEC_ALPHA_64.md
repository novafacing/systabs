
#  alpha 64-bit

| Syscall # | Name | Entry Points | # Arguments | arg0 | arg1 | arg2 | arg3 | arg4 | arg5 | arg6 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
1 | exit | sys_exit | 1 | int error_code | - | - | - | - | - | - |
2 | fork | alpha_fork | 0 | - | - | - | - | - | - | - |
3 | read | sys_read | 3 | unsigned int fd | char __user * buf | size_t count | - | - | - | - |
4 | write | sys_write | 3 | unsigned int fd | const char __user * buf | size_t count | - | - | - | - |
6 | close | sys_close | 1 | unsigned int fd | - | - | - | - | - | - |
7 | osf_wait4 | sys_osf_wait4 | 4 | pid_t pid | int __user * ustatus | int options | struct rusage32 __user * ur | - | - | - |
9 | link | sys_link | 2 | const char __user * oldname | const char __user * newname | - | - | - | - | - |
10 | unlink | sys_unlink | 1 | const char __user * pathname | - | - | - | - | - | - |
12 | chdir | sys_chdir | 1 | const char __user * filename | - | - | - | - | - | - |
13 | fchdir | sys_fchdir | 1 | unsigned int fd | - | - | - | - | - | - |
14 | mknod | sys_mknod | 3 | const char __user * filename | umode_t mode | unsigned dev | - | - | - | - |
15 | chmod | sys_chmod | 2 | const char __user * filename | umode_t mode | - | - | - | - | - |
16 | chown | sys_chown | 3 | const char __user * filename | uid_t user | gid_t group | - | - | - | - |
17 | osf_brk | sys_osf_brk | 1 | unsigned long brk | - | - | - | - | - | - |
17 | brk | sys_osf_brk | 1 | unsigned long brk | - | - | - | - | - | - |
17 | brk | sys_osf_brk | 1 | unsigned long brk | - | - | - | - | - | - |
19 | lseek | sys_lseek | 3 | unsigned int fd | off_t offset | unsigned int whence | - | - | - | - |
20 | getxpid | sys_getxpid | 0 | - | - | - | - | - | - | - |
21 | osf_mount | sys_osf_mount | 4 | unsigned long typenr | const char __user * path | int flag | void __user * data | - | - | - |
22 | umount | sys_umount | 2 | char __user * name | int flags | - | - | - | - | - |
23 | setuid | sys_setuid | 1 | uid_t uid | - | - | - | - | - | - |
24 | getxuid | sys_getxuid | 0 | - | - | - | - | - | - | - |
26 | ptrace | sys_ptrace | 4 | long request | long pid | unsigned long addr | unsigned long data | - | - | - |
33 | access | sys_access | 2 | const char __user * filename | int mode | - | - | - | - | - |
36 | sync | sys_sync | 0 | - | - | - | - | - | - | - |
37 | kill | sys_kill | 2 | pid_t pid | int sig | - | - | - | - | - |
39 | setpgid | sys_setpgid | 2 | pid_t pid | pid_t pgid | - | - | - | - | - |
41 | dup | sys_dup | 1 | unsigned int fildes | - | - | - | - | - | - |
42 | alpha_pipe | sys_alpha_pipe | 0 | - | - | - | - | - | - | - |
42 | pipe | sys_alpha_pipe | 1 | int __user * fildes | - | - | - | - | - | - |
43 | osf_set_program_attributes | sys_osf_set_program_attributes | 4 | unsigned long text_start | unsigned long text_len | unsigned long bss_start | unsigned long bss_len | - | - | - |
45 | open | sys_open | 3 | const char __user * filename | int flags | umode_t mode | - | - | - | - |
47 | getxgid | sys_getxgid | 0 | - | - | - | - | - | - | - |
48 | osf_sigprocmask | sys_osf_sigprocmask | 2 | int how | unsigned long newmask | - | - | - | - | - |
51 | acct | sys_acct | 1 | const char __user * name | - | - | - | - | - | - |
52 | sigpending | sys_sigpending | 1 | old_sigset_t __user * uset | - | - | - | - | - | - |
54 | ioctl | sys_ioctl | 3 | unsigned int fd | unsigned int cmd | unsigned long arg | - | - | - | - |
57 | symlink | sys_symlink | 2 | const char __user * oldname | const char __user * newname | - | - | - | - | - |
58 | readlink | sys_readlink | 3 | const char __user * path | char __user * buf | int bufsiz | - | - | - | - |
59 | execve | sys_execve | 3 | const char __user * filename | const char __user *const __user * argv | const char __user *const __user * envp | - | - | - | - |
61 | chroot | sys_chroot | 1 | const char __user * filename | - | - | - | - | - | - |
63 | getpgrp | sys_getpgrp | 0 | - | - | - | - | - | - | - |
64 | getpagesize | sys_getpagesize | 0 | - | - | - | - | - | - | - |
66 | vfork | alpha_vfork | 0 | - | - | - | - | - | - | - |
67 | stat | sys_newstat | 2 | const char __user * filename | struct __old_kernel_stat __user * statbuf | - | - | - | - | - |
67 | newstat | sys_newstat | 2 | const char __user * filename | struct stat __user * statbuf | - | - | - | - | - |
68 | lstat | sys_newlstat | 2 | const char __user * filename | struct __old_kernel_stat __user * statbuf | - | - | - | - | - |
68 | newlstat | sys_newlstat | 2 | const char __user * filename | struct stat __user * statbuf | - | - | - | - | - |
71 | osf_mmap | sys_osf_mmap | 6 | unsigned long addr | unsigned long len | unsigned long prot | unsigned long flags | unsigned long fd | unsigned long off | - |
73 | munmap | sys_munmap | 2 | unsigned long addr | size_t len | - | - | - | - | - |
73 | munmap | sys_munmap | 2 | unsigned long addr | size_t len | - | - | - | - | - |
74 | mprotect | sys_mprotect | 3 | unsigned long start | size_t len | unsigned long prot | - | - | - | - |
75 | madvise | sys_madvise | 3 | unsigned long start | size_t len_in | int behavior | - | - | - | - |
76 | vhangup | sys_vhangup | 0 | - | - | - | - | - | - | - |
79 | getgroups | sys_getgroups | 2 | int gidsetsize | gid_t __user * grouplist | - | - | - | - | - |
80 | setgroups | sys_setgroups | 2 | int gidsetsize | gid_t __user * grouplist | - | - | - | - | - |
87 | gethostname | sys_gethostname | 2 | char __user * name | int len | - | - | - | - | - |
88 | sethostname | sys_sethostname | 2 | char __user * name | int len | - | - | - | - | - |
89 | getdtablesize | sys_getdtablesize | 0 | - | - | - | - | - | - | - |
90 | dup2 | sys_dup2 | 2 | unsigned int oldfd | unsigned int newfd | - | - | - | - | - |
91 | fstat | sys_newfstat | 2 | unsigned int fd | struct __old_kernel_stat __user * statbuf | - | - | - | - | - |
91 | newfstat | sys_newfstat | 2 | unsigned int fd | struct stat __user * statbuf | - | - | - | - | - |
92 | fcntl | sys_fcntl | 3 | unsigned int fd | unsigned int cmd | unsigned long arg | - | - | - | - |
93 | osf_select | sys_osf_select | 5 | int n | fd_set __user * inp | fd_set __user * outp | fd_set __user * exp | struct timeval32 __user * tvp | - | - |
94 | poll | sys_poll | 3 | struct pollfd __user * ufds | unsigned int nfds | int timeout_msecs | - | - | - | - |
95 | fsync | sys_fsync | 1 | unsigned int fd | - | - | - | - | - | - |
96 | setpriority | sys_setpriority | 3 | int which | int who | int niceval | - | - | - | - |
97 | socket | sys_socket | 3 | int family | int type | int protocol | - | - | - | - |
98 | connect | sys_connect | 3 | int fd | struct sockaddr __user * uservaddr | int addrlen | - | - | - | - |
99 | accept | sys_accept | 3 | int fd | struct sockaddr __user * upeer_sockaddr | int __user * upeer_addrlen | - | - | - | - |
100 | osf_getpriority | sys_osf_getpriority | 2 | int which | int who | - | - | - | - | - |
100 | getpriority | sys_osf_getpriority | 2 | int which | int who | - | - | - | - | - |
101 | send | sys_send | 4 | int fd | void __user * buff | size_t len | unsigned int flags | - | - | - |
102 | recv | sys_recv | 4 | int fd | void __user * ubuf | size_t size | unsigned int flags | - | - | - |
104 | bind | sys_bind | 3 | int fd | struct sockaddr __user * umyaddr | int addrlen | - | - | - | - |
105 | setsockopt | sys_setsockopt | 5 | int fd | int level | int optname | char __user * optval | int optlen | - | - |
106 | listen | sys_listen | 2 | int fd | int backlog | - | - | - | - | - |
111 | sigsuspend | sys_sigsuspend | 1 | old_sigset_t mask | - | - | - | - | - | - |
111 | sigsuspend | sys_sigsuspend | 3 | int unused1 | int unused2 | old_sigset_t mask | - | - | - | - |
112 | osf_sigstack | sys_osf_sigstack | 2 | struct sigstack __user * uss | struct sigstack __user * uoss | - | - | - | - | - |
113 | recvmsg | sys_recvmsg | 3 | int fd | struct user_msghdr __user * msg | unsigned int flags | - | - | - | - |
114 | sendmsg | sys_sendmsg | 3 | int fd | struct user_msghdr __user * msg | unsigned int flags | - | - | - | - |
116 | osf_gettimeofday | sys_osf_gettimeofday | 2 | struct timeval32 __user * tv | struct timezone __user * tz | - | - | - | - | - |
117 | osf_getrusage | sys_osf_getrusage | 2 | int who | struct rusage32 __user * ru | - | - | - | - | - |
118 | getsockopt | sys_getsockopt | 5 | int fd | int level | int optname | char __user * optval | int __user * optlen | - | - |
120 | osf_readv | sys_osf_readv | 3 | unsigned long fd | const struct iovec __user * vector | unsigned long count | - | - | - | - |
120 | readv | sys_osf_readv | 3 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | - | - | - | - |
121 | osf_writev | sys_osf_writev | 3 | unsigned long fd | const struct iovec __user * vector | unsigned long count | - | - | - | - |
121 | writev | sys_osf_writev | 3 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | - | - | - | - |
122 | osf_settimeofday | sys_osf_settimeofday | 2 | struct timeval32 __user * tv | struct timezone __user * tz | - | - | - | - | - |
123 | fchown | sys_fchown | 3 | unsigned int fd | uid_t user | gid_t group | - | - | - | - |
124 | fchmod | sys_fchmod | 2 | unsigned int fd | umode_t mode | - | - | - | - | - |
125 | recvfrom | sys_recvfrom | 6 | int fd | void __user * ubuf | size_t size | unsigned int flags | struct sockaddr __user * addr | int __user * addr_len | - |
126 | setreuid | sys_setreuid | 2 | uid_t ruid | uid_t euid | - | - | - | - | - |
127 | setregid | sys_setregid | 2 | gid_t rgid | gid_t egid | - | - | - | - | - |
128 | rename | sys_rename | 2 | const char __user * oldname | const char __user * newname | - | - | - | - | - |
129 | truncate | sys_truncate | 2 | const char __user * path | long length | - | - | - | - | - |
130 | ftruncate | sys_ftruncate | 2 | unsigned int fd | unsigned long length | - | - | - | - | - |
131 | flock | sys_flock | 2 | unsigned int fd | unsigned int cmd | - | - | - | - | - |
132 | setgid | sys_setgid | 1 | gid_t gid | - | - | - | - | - | - |
133 | sendto | sys_sendto | 6 | int fd | void __user * buff | size_t len | unsigned int flags | struct sockaddr __user * addr | int addr_len | - |
134 | shutdown | sys_shutdown | 2 | int fd | int how | - | - | - | - | - |
135 | socketpair | sys_socketpair | 4 | int family | int type | int protocol | int __user * usockvec | - | - | - |
136 | mkdir | sys_mkdir | 2 | const char __user * pathname | umode_t mode | - | - | - | - | - |
137 | rmdir | sys_rmdir | 1 | const char __user * pathname | - | - | - | - | - | - |
138 | osf_utimes | sys_osf_utimes | 2 | const char __user * filename | struct timeval32 __user * tvs | - | - | - | - | - |
141 | getpeername | sys_getpeername | 3 | int fd | struct sockaddr __user * usockaddr | int __user * usockaddr_len | - | - | - | - |
144 | getrlimit | sys_getrlimit | 2 | unsigned int resource | struct rlimit __user * rlim | - | - | - | - | - |
145 | setrlimit | sys_setrlimit | 2 | unsigned int resource | struct rlimit __user * rlim | - | - | - | - | - |
147 | setsid | sys_setsid | 0 | - | - | - | - | - | - | - |
148 | quotactl | sys_quotactl | 4 | unsigned int cmd | const char __user * special | qid_t id | void __user * addr | - | - | - |
150 | getsockname | sys_getsockname | 3 | int fd | struct sockaddr __user * usockaddr | int __user * usockaddr_len | - | - | - | - |
159 | osf_getdirentries | sys_osf_getdirentries | 4 | unsigned int fd | struct osf_dirent __user * dirent | unsigned int count | long __user * basep | - | - | - |
160 | osf_statfs | sys_osf_statfs | 3 | const char __user * pathname | struct osf_statfs __user * buffer | unsigned long bufsiz | - | - | - | - |
161 | osf_fstatfs | sys_osf_fstatfs | 3 | unsigned long fd | struct osf_statfs __user * buffer | unsigned long bufsiz | - | - | - | - |
165 | osf_getdomainname | sys_osf_getdomainname | 2 | char __user * name | int namelen | - | - | - | - | - |
166 | setdomainname | sys_setdomainname | 2 | char __user * name | int len | - | - | - | - | - |
172 | getpid |  | 0 | - | - | - | - | - | - | - |
174 | getuid |  | 0 | - | - | - | - | - | - | - |
176 | getgid |  | 0 | - | - | - | - | - | - | - |
199 | swapon | sys_swapon | 2 | const char __user * specialfile | int swap_flags | - | - | - | - | - |
200 | msgctl | sys_old_msgctl | 3 | int msqid | int cmd | struct msqid_ds __user * buf | - | - | - | - |
200 | old_msgctl | sys_old_msgctl | 3 | int msqid | int cmd | struct msqid_ds __user * buf | - | - | - | - |
201 | msgget | sys_msgget | 2 | key_t key | int msgflg | - | - | - | - | - |
202 | msgrcv | sys_msgrcv | 5 | int msqid | struct msgbuf __user * msgp | size_t msgsz | long msgtyp | int msgflg | - | - |
203 | msgsnd | sys_msgsnd | 4 | int msqid | struct msgbuf __user * msgp | size_t msgsz | int msgflg | - | - | - |
204 | semctl | sys_old_semctl | 4 | int semid | int semnum | int cmd | unsigned long arg | - | - | - |
204 | old_semctl | sys_old_semctl | 4 | int semid | int semnum | int cmd | unsigned long arg | - | - | - |
205 | semget | sys_semget | 3 | key_t key | int nsems | int semflg | - | - | - | - |
206 | semop | sys_semop | 3 | int semid | struct sembuf __user * tsops | unsigned nsops | - | - | - | - |
207 | osf_utsname | sys_osf_utsname | 1 | char __user * name | - | - | - | - | - | - |
208 | lchown | sys_lchown | 3 | const char __user * filename | uid_t user | gid_t group | - | - | - | - |
209 | shmat | sys_shmat | 3 | int shmid | char __user * shmaddr | int shmflg | - | - | - | - |
210 | shmctl | sys_old_shmctl | 3 | int shmid | int cmd | struct shmid_ds __user * buf | - | - | - | - |
210 | old_shmctl | sys_old_shmctl | 3 | int shmid | int cmd | struct shmid_ds __user * buf | - | - | - | - |
211 | shmdt | sys_shmdt | 1 | char __user * shmaddr | - | - | - | - | - | - |
212 | shmget | sys_shmget | 3 | key_t key | size_t size | int shmflg | - | - | - | - |
217 | msync | sys_msync | 3 | unsigned long start | size_t len | int flags | - | - | - | - |
224 | osf_stat | sys_osf_stat | 2 | char __user * name | struct osf_stat __user * buf | - | - | - | - | - |
225 | osf_lstat | sys_osf_lstat | 2 | char __user * name | struct osf_stat __user * buf | - | - | - | - | - |
226 | osf_fstat | sys_osf_fstat | 2 | int fd | struct osf_stat __user * buf | - | - | - | - | - |
227 | osf_statfs64 | sys_osf_statfs64 | 3 | char __user * pathname | struct osf_statfs64 __user * buffer | unsigned long bufsiz | - | - | - | - |
228 | osf_fstatfs64 | sys_osf_fstatfs64 | 3 | unsigned long fd | struct osf_statfs64 __user * buffer | unsigned long bufsiz | - | - | - | - |
233 | getpgid | sys_getpgid | 1 | pid_t pid | - | - | - | - | - | - |
234 | getsid | sys_getsid | 1 | pid_t pid | - | - | - | - | - | - |
235 | sigaltstack | sys_sigaltstack | 2 | const stack_t __user * uss | stack_t __user * uoss | - | - | - | - | - |
241 | osf_sysinfo | sys_osf_sysinfo | 3 | int command | char __user * buf | long count | - | - | - | - |
244 | osf_proplist_syscall | sys_osf_proplist_syscall | 2 | enum pl_code code | union pl_args __user * args | - | - | - | - | - |
251 | osf_usleep_thread | sys_osf_usleep_thread | 2 | struct timeval32 __user * sleep | struct timeval32 __user * remain | - | - | - | - | - |
254 | sysfs | sys_sysfs | 3 | int option | unsigned long arg1 | unsigned long arg2 | - | - | - | - |
256 | osf_getsysinfo | sys_osf_getsysinfo | 5 | unsigned long op | void __user * buffer | unsigned long nbytes | int __user * start | void __user * arg | - | - |
257 | osf_setsysinfo | sys_osf_setsysinfo | 5 | unsigned long op | void __user * buffer | unsigned long nbytes | int __user * start | void __user * arg | - | - |
294 | kexec_file_load |  | 5 | int kernel_fd | int initrd_fd | unsigned long cmdline_len | const char __user * cmdline_ptr | unsigned long flags | - | - |
301 | sethae | sys_sethae | 1 | unsigned long val | - | - | - | - | - | - |
302 | mount | sys_mount | 5 | char __user * dev_name | char __user * dir_name | char __user * type | unsigned long flags | void __user * data | - | - |
303 | old_adjtimex | sys_old_adjtimex | 1 | struct timex32 __user * txc_p | - | - | - | - | - | - |
304 | swapoff | sys_swapoff | 1 | const char __user * specialfile | - | - | - | - | - | - |
305 | getdents | sys_getdents | 3 | unsigned int fd | struct linux_dirent __user * dirent | unsigned int count | - | - | - | - |
307 | init_module | sys_init_module | 3 | void __user * umod | unsigned long len | const char __user * uargs | - | - | - | - |
308 | delete_module | sys_delete_module | 2 | const char __user * name_user | unsigned int flags | - | - | - | - | - |
310 | syslog | sys_syslog | 3 | int type | char __user * buf | int len | - | - | - | - |
311 | reboot | sys_reboot | 4 | int magic1 | int magic2 | unsigned int cmd | void __user * arg | - | - | - |
312 | clone | alpha_clone | 5 | unsigned long clone_flags | unsigned long newsp | int __user * parent_tidptr | unsigned long tls | int __user * child_tidptr | - | - |
312 | clone | alpha_clone | 5 | unsigned long newsp | unsigned long clone_flags | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - | - |
312 | clone | alpha_clone | 6 | unsigned long clone_flags | unsigned long newsp | int stack_size | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - |
312 | clone | alpha_clone | 5 | unsigned long clone_flags | unsigned long newsp | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - | - |
313 | uselib | sys_uselib | 1 | const char __user * library | - | - | - | - | - | - |
314 | mlock | sys_mlock | 2 | unsigned long start | size_t len | - | - | - | - | - |
315 | munlock | sys_munlock | 2 | unsigned long start | size_t len | - | - | - | - | - |
316 | mlockall | sys_mlockall | 1 | int flags | - | - | - | - | - | - |
317 | munlockall | sys_munlockall | 0 | - | - | - | - | - | - | - |
321 | oldumount | sys_oldumount | 1 | char __user * name | - | - | - | - | - | - |
323 | times | sys_times | 1 | struct tms __user * tbuf | - | - | - | - | - | - |
324 | personality | sys_personality | 1 | unsigned int personality | - | - | - | - | - | - |
325 | setfsuid | sys_setfsuid | 1 | uid_t uid | - | - | - | - | - | - |
326 | setfsgid | sys_setfsgid | 1 | gid_t gid | - | - | - | - | - | - |
327 | ustat | sys_ustat | 2 | unsigned dev | struct ustat __user * ubuf | - | - | - | - | - |
328 | statfs | sys_statfs | 2 | const char __user * pathname | struct statfs __user * buf | - | - | - | - | - |
329 | fstatfs | sys_fstatfs | 2 | unsigned int fd | struct statfs __user * buf | - | - | - | - | - |
330 | sched_setparam | sys_sched_setparam | 2 | pid_t pid | struct sched_param __user * param | - | - | - | - | - |
331 | sched_getparam | sys_sched_getparam | 2 | pid_t pid | struct sched_param __user * param | - | - | - | - | - |
332 | sched_setscheduler | sys_sched_setscheduler | 3 | pid_t pid | int policy | struct sched_param __user * param | - | - | - | - |
333 | sched_getscheduler | sys_sched_getscheduler | 1 | pid_t pid | - | - | - | - | - | - |
334 | sched_yield | sys_sched_yield | 0 | - | - | - | - | - | - | - |
335 | sched_get_priority_max | sys_sched_get_priority_max | 1 | int policy | - | - | - | - | - | - |
336 | sched_get_priority_min | sys_sched_get_priority_min | 1 | int policy | - | - | - | - | - | - |
337 | sched_rr_get_interval | sys_sched_rr_get_interval | 2 | pid_t pid | struct __kernel_timespec __user * interval | - | - | - | - | - |
339 | newuname | sys_newuname | 1 | struct new_utsname __user * name | - | - | - | - | - | - |
339 | uname | sys_newuname | 1 | struct old_utsname __user * name | - | - | - | - | - | - |
340 | nanosleep | sys_nanosleep | 2 | struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - | - | - |
341 | mremap | sys_mremap | 5 | unsigned long addr | unsigned long old_len | unsigned long new_len | unsigned long flags | unsigned long new_addr | - | - |
341 | mremap | sys_mremap | 5 | unsigned long addr | unsigned long old_len | unsigned long new_len | unsigned long flags | unsigned long new_addr | - | - |
343 | setresuid | sys_setresuid | 3 | uid_t ruid | uid_t euid | uid_t suid | - | - | - | - |
344 | getresuid | sys_getresuid | 3 | uid_t __user * ruidp | uid_t __user * euidp | uid_t __user * suidp | - | - | - | - |
345 | pciconfig_read | sys_pciconfig_read | 5 | unsigned long bus | unsigned long dfn | unsigned long off | unsigned long len | void __user * buf | - | - |
346 | pciconfig_write | sys_pciconfig_write | 5 | unsigned long bus | unsigned long dfn | unsigned long off | unsigned long len | void __user * buf | - | - |
349 | pread64 | sys_pread64 | 4 | unsigned int fd | char __user * buf | size_t count | loff_t pos | - | - | - |
350 | pwrite64 | sys_pwrite64 | 4 | unsigned int fd | const char __user * buf | size_t count | loff_t pos | - | - | - |
353 | rt_sigprocmask | sys_rt_sigprocmask | 4 | int how | sigset_t __user * nset | sigset_t __user * oset | size_t sigsetsize | - | - | - |
354 | rt_sigpending | sys_rt_sigpending | 2 | sigset_t __user * uset | size_t sigsetsize | - | - | - | - | - |
355 | rt_sigtimedwait | sys_rt_sigtimedwait | 4 | const sigset_t __user * uthese | siginfo_t __user * uinfo | const struct __kernel_timespec __user * uts | size_t sigsetsize | - | - | - |
356 | rt_sigqueueinfo | sys_rt_sigqueueinfo | 3 | pid_t pid | int sig | siginfo_t __user * uinfo | - | - | - | - |
357 | rt_sigsuspend | sys_rt_sigsuspend | 2 | sigset_t __user * unewset | size_t sigsetsize | - | - | - | - | - |
358 | select | sys_select | 5 | int n | fd_set __user * inp | fd_set __user * outp | fd_set __user * exp | struct __kernel_old_timeval __user * tvp | - | - |
359 | gettimeofday | sys_gettimeofday | 2 | struct __kernel_old_timeval __user * tv | struct timezone __user * tz | - | - | - | - | - |
360 | settimeofday | sys_settimeofday | 2 | struct __kernel_old_timeval __user * tv | struct timezone __user * tz | - | - | - | - | - |
361 | getitimer | sys_getitimer | 2 | int which | struct __kernel_old_itimerval __user * value | - | - | - | - | - |
362 | setitimer | sys_setitimer | 3 | int which | struct __kernel_old_itimerval __user * value | struct __kernel_old_itimerval __user * ovalue | - | - | - | - |
363 | utimes | sys_utimes | 2 | char __user * filename | struct __kernel_old_timeval __user * utimes | - | - | - | - | - |
364 | getrusage | sys_getrusage | 2 | int who | struct rusage __user * ru | - | - | - | - | - |
366 | adjtimex | sys_adjtimex | 1 | struct __kernel_timex __user * txc_p | - | - | - | - | - | - |
367 | getcwd | sys_getcwd | 2 | char __user * buf | unsigned long size | - | - | - | - | - |
368 | capget | sys_capget | 2 | cap_user_header_t header | cap_user_data_t dataptr | - | - | - | - | - |
369 | capset | sys_capset | 2 | cap_user_header_t header | const cap_user_data_t data | - | - | - | - | - |
370 | sendfile | sys_sendfile64 | 4 | int out_fd | int in_fd | off_t __user * offset | size_t count | - | - | - |
370 | sendfile64 | sys_sendfile64 | 4 | int out_fd | int in_fd | loff_t __user * offset | size_t count | - | - | - |
371 | setresgid | sys_setresgid | 3 | gid_t rgid | gid_t egid | gid_t sgid | - | - | - | - |
372 | getresgid | sys_getresgid | 3 | gid_t __user * rgidp | gid_t __user * egidp | gid_t __user * sgidp | - | - | - | - |
374 | pivot_root | sys_pivot_root | 2 | const char __user * new_root | const char __user * put_old | - | - | - | - | - |
375 | mincore | sys_mincore | 3 | unsigned long start | size_t len | unsigned char __user * vec | - | - | - | - |
376 | pciconfig_iobase | sys_pciconfig_iobase | 3 | long which | unsigned long bus | unsigned long dfn | - | - | - | - |
376 | pciconfig_iobase | sys_pciconfig_iobase | 3 | long which | unsigned long bus | unsigned long dfn | - | - | - | - |
377 | getdents64 | sys_getdents64 | 3 | unsigned int fd | struct linux_dirent64 __user * dirent | unsigned int count | - | - | - | - |
378 | gettid | sys_gettid | 0 | - | - | - | - | - | - | - |
379 | readahead | sys_readahead | 3 | int fd | loff_t offset | size_t count | - | - | - | - |
381 | tkill | sys_tkill | 2 | pid_t pid | int sig | - | - | - | - | - |
382 | setxattr | sys_setxattr | 5 | const char __user * pathname | const char __user * name | const void __user * value | size_t size | int flags | - | - |
383 | lsetxattr | sys_lsetxattr | 5 | const char __user * pathname | const char __user * name | const void __user * value | size_t size | int flags | - | - |
384 | fsetxattr | sys_fsetxattr | 5 | int fd | const char __user * name | const void __user * value | size_t size | int flags | - | - |
385 | getxattr | sys_getxattr | 4 | const char __user * pathname | const char __user * name | void __user * value | size_t size | - | - | - |
386 | lgetxattr | sys_lgetxattr | 4 | const char __user * pathname | const char __user * name | void __user * value | size_t size | - | - | - |
387 | fgetxattr | sys_fgetxattr | 4 | int fd | const char __user * name | void __user * value | size_t size | - | - | - |
388 | listxattr | sys_listxattr | 3 | const char __user * pathname | char __user * list | size_t size | - | - | - | - |
389 | llistxattr | sys_llistxattr | 3 | const char __user * pathname | char __user * list | size_t size | - | - | - | - |
390 | flistxattr | sys_flistxattr | 3 | int fd | char __user * list | size_t size | - | - | - | - |
391 | removexattr | sys_removexattr | 2 | const char __user * pathname | const char __user * name | - | - | - | - | - |
392 | lremovexattr | sys_lremovexattr | 2 | const char __user * pathname | const char __user * name | - | - | - | - | - |
393 | fremovexattr | sys_fremovexattr | 2 | int fd | const char __user * name | - | - | - | - | - |
394 | futex | sys_futex | 6 | u32 __user * uaddr | int op | u32 val | const struct __kernel_timespec __user * utime | u32 __user * uaddr2 | u32 val3 | - |
395 | sched_setaffinity | sys_sched_setaffinity | 3 | pid_t pid | unsigned int len | unsigned long __user * user_mask_ptr | - | - | - | - |
396 | sched_getaffinity | sys_sched_getaffinity | 3 | pid_t pid | unsigned int len | unsigned long __user * user_mask_ptr | - | - | - | - |
398 | io_setup | sys_io_setup | 2 | unsigned nr_events | aio_context_t __user * ctxp | - | - | - | - | - |
399 | io_destroy | sys_io_destroy | 1 | aio_context_t ctx | - | - | - | - | - | - |
400 | io_getevents | sys_io_getevents | 5 | aio_context_t ctx_id | long min_nr | long nr | struct io_event __user * events | struct __kernel_timespec __user * timeout | - | - |
401 | io_submit | sys_io_submit | 3 | aio_context_t ctx_id | long nr | struct iocb __user * __user * iocbpp | - | - | - | - |
402 | io_cancel | sys_io_cancel | 3 | aio_context_t ctx_id | struct iocb __user * iocb | struct io_event __user * result | - | - | - | - |
405 | exit_group | sys_exit_group | 1 | int error_code | - | - | - | - | - | - |
407 | epoll_create | sys_epoll_create | 1 | int size | - | - | - | - | - | - |
408 | epoll_ctl | sys_epoll_ctl | 4 | int epfd | int op | int fd | struct epoll_event __user * event | - | - | - |
409 | epoll_wait | sys_epoll_wait | 4 | int epfd | struct epoll_event __user * events | int maxevents | int timeout | - | - | - |
410 | remap_file_pages | sys_remap_file_pages | 5 | unsigned long start | unsigned long size | unsigned long prot | unsigned long pgoff | unsigned long flags | - | - |
411 | set_tid_address | sys_set_tid_address | 1 | int __user * tidptr | - | - | - | - | - | - |
412 | restart_syscall | sys_restart_syscall | 0 | - | - | - | - | - | - | - |
413 | fadvise64 | sys_fadvise64 | 4 | int fd | loff_t offset | size_t len | int advice | - | - | - |
414 | timer_create | sys_timer_create | 3 | const clockid_t which_clock | struct sigevent __user * timer_event_spec | timer_t __user * created_timer_id | - | - | - | - |
415 | timer_settime | sys_timer_settime | 4 | timer_t timer_id | int flags | const struct __kernel_itimerspec __user * new_setting | struct __kernel_itimerspec __user * old_setting | - | - | - |
416 | timer_gettime | sys_timer_gettime | 2 | timer_t timer_id | struct __kernel_itimerspec __user * setting | - | - | - | - | - |
417 | timer_getoverrun | sys_timer_getoverrun | 1 | timer_t timer_id | - | - | - | - | - | - |
418 | timer_delete | sys_timer_delete | 1 | timer_t timer_id | - | - | - | - | - | - |
419 | clock_settime | sys_clock_settime | 2 | const clockid_t which_clock | const struct __kernel_timespec __user * tp | - | - | - | - | - |
419 | clock_settime | sys_clock_settime | 2 | const clockid_t which_clock | const struct __kernel_timespec __user * tp | - | - | - | - | - |
420 | clock_gettime | sys_clock_gettime | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
420 | clock_gettime | sys_clock_gettime | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
421 | clock_getres | sys_clock_getres | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
421 | clock_getres | sys_clock_getres | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
422 | clock_nanosleep | sys_clock_nanosleep | 4 | const clockid_t which_clock | int flags | const struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - |
422 | clock_nanosleep | sys_clock_nanosleep | 4 | const clockid_t which_clock | int flags | const struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - |
423 | semtimedop | sys_semtimedop | 4 | int semid | struct sembuf __user * tsops | unsigned int nsops | const struct __kernel_timespec __user * timeout | - | - | - |
424 | tgkill | sys_tgkill | 3 | pid_t tgid | pid_t pid | int sig | - | - | - | - |
425 | stat64 | sys_stat64 | 2 | const char __user * filename | struct stat64 __user * statbuf | - | - | - | - | - |
426 | lstat64 | sys_lstat64 | 2 | const char __user * filename | struct stat64 __user * statbuf | - | - | - | - | - |
427 | fstat64 | sys_fstat64 | 2 | unsigned long fd | struct stat64 __user * statbuf | - | - | - | - | - |
429 | mbind | sys_ni_syscall | 6 | unsigned long start | unsigned long len | unsigned long mode | const unsigned long __user * nmask | unsigned long maxnode | unsigned int flags | - |
430 | get_mempolicy | sys_ni_syscall | 5 | int __user * policy | unsigned long __user * nmask | unsigned long maxnode | unsigned long addr | unsigned long flags | - | - |
431 | set_mempolicy | sys_ni_syscall | 3 | int mode | const unsigned long __user * nmask | unsigned long maxnode | - | - | - | - |
432 | mq_open | sys_mq_open | 4 | const char __user * u_name | int oflag | umode_t mode | struct mq_attr __user * u_attr | - | - | - |
433 | mq_unlink | sys_mq_unlink | 1 | const char __user * u_name | - | - | - | - | - | - |
434 | mq_timedsend | sys_mq_timedsend | 5 | mqd_t mqdes | const char __user * u_msg_ptr | size_t msg_len | unsigned int msg_prio | const struct __kernel_timespec __user * u_abs_timeout | - | - |
435 | mq_timedreceive | sys_mq_timedreceive | 5 | mqd_t mqdes | char __user * u_msg_ptr | size_t msg_len | unsigned int __user * u_msg_prio | const struct __kernel_timespec __user * u_abs_timeout | - | - |
439 | add_key | sys_add_key | 5 | const char __user * _type | const char __user * _description | const void __user * _payload | size_t plen | key_serial_t ringid | - | - |
440 | request_key | sys_request_key | 4 | const char __user * _type | const char __user * _description | const char __user * _callout_info | key_serial_t destringid | - | - | - |
441 | keyctl | sys_keyctl | 5 | int option | unsigned long arg2 | unsigned long arg3 | unsigned long arg4 | unsigned long arg5 | - | - |
442 | ioprio_set | sys_ioprio_set | 3 | int which | int who | int ioprio | - | - | - | - |
443 | ioprio_get | sys_ioprio_get | 2 | int which | int who | - | - | - | - | - |
444 | inotify_init | sys_inotify_init | 0 | - | - | - | - | - | - | - |
445 | inotify_add_watch | sys_inotify_add_watch | 3 | int fd | const char __user * pathname | u32 mask | - | - | - | - |
446 | inotify_rm_watch | sys_inotify_rm_watch | 2 | int fd | __s32 wd | - | - | - | - | - |
447 | fdatasync | sys_fdatasync | 1 | unsigned int fd | - | - | - | - | - | - |
448 | kexec_load | sys_kexec_load | 4 | unsigned long entry | unsigned long nr_segments | struct kexec_segment __user * segments | unsigned long flags | - | - | - |
449 | migrate_pages | sys_migrate_pages | 4 | pid_t pid | unsigned long maxnode | const unsigned long __user * old_nodes | const unsigned long __user * new_nodes | - | - | - |
450 | openat | sys_openat | 4 | int dfd | const char __user * filename | int flags | umode_t mode | - | - | - |
451 | mkdirat | sys_mkdirat | 3 | int dfd | const char __user * pathname | umode_t mode | - | - | - | - |
452 | mknodat | sys_mknodat | 4 | int dfd | const char __user * filename | umode_t mode | unsigned int dev | - | - | - |
453 | fchownat | sys_fchownat | 5 | int dfd | const char __user * filename | uid_t user | gid_t group | int flag | - | - |
454 | futimesat | sys_futimesat | 3 | int dfd | const char __user * filename | struct __kernel_old_timeval __user * utimes | - | - | - | - |
455 | fstatat64 | sys_fstatat64 | 4 | int dfd | const char __user * filename | struct stat64 __user * statbuf | int flag | - | - | - |
456 | unlinkat | sys_unlinkat | 3 | int dfd | const char __user * pathname | int flag | - | - | - | - |
457 | renameat | sys_renameat | 4 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | - | - | - |
458 | linkat | sys_linkat | 5 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | int flags | - | - |
459 | symlinkat | sys_symlinkat | 3 | const char __user * oldname | int newdfd | const char __user * newname | - | - | - | - |
460 | readlinkat | sys_readlinkat | 4 | int dfd | const char __user * pathname | char __user * buf | int bufsiz | - | - | - |
461 | fchmodat | sys_fchmodat | 3 | int dfd | const char __user * filename | umode_t mode | - | - | - | - |
462 | faccessat | sys_faccessat | 3 | int dfd | const char __user * filename | int mode | - | - | - | - |
463 | pselect6 | sys_pselect6 | 6 | int n | fd_set __user * inp | fd_set __user * outp | fd_set __user * exp | struct __kernel_timespec __user * tsp | void __user * sig | - |
464 | ppoll | sys_ppoll | 5 | struct pollfd __user * ufds | unsigned int nfds | struct __kernel_timespec __user * tsp | const sigset_t __user * sigmask | size_t sigsetsize | - | - |
465 | unshare | sys_unshare | 1 | unsigned long unshare_flags | - | - | - | - | - | - |
466 | set_robust_list | sys_set_robust_list | 2 | struct robust_list_head __user * head | size_t len | - | - | - | - | - |
467 | get_robust_list | sys_get_robust_list | 3 | int pid | struct robust_list_head __user * __user * head_ptr | size_t __user * len_ptr | - | - | - | - |
468 | splice | sys_splice | 6 | int fd_in | loff_t __user * off_in | int fd_out | loff_t __user * off_out | size_t len | unsigned int flags | - |
469 | sync_file_range | sys_sync_file_range | 4 | int fd | loff_t offset | loff_t nbytes | unsigned int flags | - | - | - |
470 | tee | sys_tee | 4 | int fdin | int fdout | size_t len | unsigned int flags | - | - | - |
471 | vmsplice | sys_vmsplice | 4 | int fd | const struct iovec __user * uiov | unsigned long nr_segs | unsigned int flags | - | - | - |
472 | move_pages | sys_move_pages | 6 | pid_t pid | unsigned long nr_pages | const void __user * __user * pages | const int __user * nodes | int __user * status | int flags | - |
474 | epoll_pwait | sys_epoll_pwait | 6 | int epfd | struct epoll_event __user * events | int maxevents | int timeout | const sigset_t __user * sigmask | size_t sigsetsize | - |
475 | utimensat | sys_utimensat | 4 | int dfd | const char __user * filename | struct __kernel_timespec __user * utimes | int flags | - | - | - |
476 | signalfd | sys_signalfd | 3 | int ufd | sigset_t __user * user_mask | size_t sizemask | - | - | - | - |
478 | eventfd | sys_eventfd | 1 | unsigned int count | - | - | - | - | - | - |
479 | recvmmsg | sys_recvmmsg | 5 | int fd | struct mmsghdr __user * mmsg | unsigned int vlen | unsigned int flags | struct __kernel_timespec __user * timeout | - | - |
480 | fallocate | sys_fallocate | 4 | int fd | int mode | loff_t offset | loff_t len | - | - | - |
481 | timerfd_create | sys_timerfd_create | 2 | int clockid | int flags | - | - | - | - | - |
482 | timerfd_settime | sys_timerfd_settime | 4 | int ufd | int flags | const struct __kernel_itimerspec __user * utmr | struct __kernel_itimerspec __user * otmr | - | - | - |
483 | timerfd_gettime | sys_timerfd_gettime | 2 | int ufd | struct __kernel_itimerspec __user * otmr | - | - | - | - | - |
484 | signalfd4 | sys_signalfd4 | 4 | int ufd | sigset_t __user * user_mask | size_t sizemask | int flags | - | - | - |
485 | eventfd2 | sys_eventfd2 | 2 | unsigned int count | int flags | - | - | - | - | - |
486 | epoll_create1 | sys_epoll_create1 | 1 | int flags | - | - | - | - | - | - |
487 | dup3 | sys_dup3 | 3 | unsigned int oldfd | unsigned int newfd | int flags | - | - | - | - |
488 | pipe2 | sys_pipe2 | 2 | int __user * fildes | int flags | - | - | - | - | - |
489 | inotify_init1 | sys_inotify_init1 | 1 | int flags | - | - | - | - | - | - |
490 | preadv | sys_preadv | 5 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | - | - |
491 | pwritev | sys_pwritev | 5 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | - | - |
492 | rt_tgsigqueueinfo | sys_rt_tgsigqueueinfo | 4 | pid_t tgid | pid_t pid | int sig | siginfo_t __user * uinfo | - | - | - |
493 | perf_event_open | sys_perf_event_open | 5 | struct perf_event_attr __user * attr_uptr | pid_t pid | int cpu | int group_fd | unsigned long flags | - | - |
494 | fanotify_init | sys_fanotify_init | 2 | unsigned int flags | unsigned int event_f_flags | - | - | - | - | - |
495 | fanotify_mark | sys_fanotify_mark | 5 | int fanotify_fd | unsigned int flags | __u64 mask | int dfd | const char __user * pathname | - | - |
496 | prlimit64 | sys_prlimit64 | 4 | pid_t pid | unsigned int resource | const struct rlimit64 __user * new_rlim | struct rlimit64 __user * old_rlim | - | - | - |
497 | name_to_handle_at | sys_name_to_handle_at | 5 | int dfd | const char __user * name | struct file_handle __user * handle | int __user * mnt_id | int flag | - | - |
498 | open_by_handle_at | sys_open_by_handle_at | 3 | int mountdirfd | struct file_handle __user * handle | int flags | - | - | - | - |
499 | clock_adjtime | sys_clock_adjtime | 2 | const clockid_t which_clock | struct __kernel_timex __user * utx | - | - | - | - | - |
500 | syncfs | sys_syncfs | 1 | int fd | - | - | - | - | - | - |
501 | setns | sys_setns | 2 | int fd | int flags | - | - | - | - | - |
502 | accept4 | sys_accept4 | 4 | int fd | struct sockaddr __user * upeer_sockaddr | int __user * upeer_addrlen | int flags | - | - | - |
503 | sendmmsg | sys_sendmmsg | 4 | int fd | struct mmsghdr __user * mmsg | unsigned int vlen | unsigned int flags | - | - | - |
504 | process_vm_readv | sys_process_vm_readv | 6 | pid_t pid | const struct iovec __user * lvec | unsigned long liovcnt | const struct iovec __user * rvec | unsigned long riovcnt | unsigned long flags | - |
505 | process_vm_writev | sys_process_vm_writev | 6 | pid_t pid | const struct iovec __user * lvec | unsigned long liovcnt | const struct iovec __user * rvec | unsigned long riovcnt | unsigned long flags | - |
506 | kcmp | sys_kcmp | 5 | pid_t pid1 | pid_t pid2 | int type | unsigned long idx1 | unsigned long idx2 | - | - |
507 | finit_module | sys_finit_module | 3 | int fd | const char __user * uargs | int flags | - | - | - | - |
508 | sched_setattr | sys_sched_setattr | 3 | pid_t pid | struct sched_attr __user * uattr | unsigned int flags | - | - | - | - |
509 | sched_getattr | sys_sched_getattr | 4 | pid_t pid | struct sched_attr __user * uattr | unsigned int usize | unsigned int flags | - | - | - |
510 | renameat2 | sys_renameat2 | 5 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | unsigned int flags | - | - |
511 | getrandom | sys_getrandom | 3 | char __user * buf | size_t count | unsigned int flags | - | - | - | - |
512 | memfd_create | sys_memfd_create | 2 | const char __user * uname | unsigned int flags | - | - | - | - | - |
513 | execveat | sys_execveat | 5 | int fd | const char __user * filename | const char __user *const __user * argv | const char __user *const __user * envp | int flags | - | - |
514 | seccomp | sys_seccomp | 3 | unsigned int op | unsigned int flags | void __user * uargs | - | - | - | - |
515 | bpf | sys_bpf | 3 | int cmd | union bpf_attr __user * uattr | unsigned int size | - | - | - | - |
516 | userfaultfd | sys_userfaultfd | 1 | int flags | - | - | - | - | - | - |
517 | membarrier | sys_membarrier | 3 | int cmd | unsigned int flags | int cpu_id | - | - | - | - |
518 | mlock2 | sys_mlock2 | 3 | unsigned long start | size_t len | int flags | - | - | - | - |
519 | copy_file_range | sys_copy_file_range | 6 | int fd_in | loff_t __user * off_in | int fd_out | loff_t __user * off_out | size_t len | unsigned int flags | - |
520 | preadv2 | sys_preadv2 | 6 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | rwf_t flags | - |
521 | pwritev2 | sys_pwritev2 | 6 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | rwf_t flags | - |
522 | statx | sys_statx | 5 | int dfd | const char __user * filename | unsigned flags | unsigned int mask | struct statx __user * buffer | - | - |
523 | io_pgetevents | sys_io_pgetevents | 6 | aio_context_t ctx_id | long min_nr | long nr | struct io_event __user * events | struct __kernel_timespec __user * timeout | const struct __aio_sigset __user * usig | - |
524 | pkey_mprotect | sys_pkey_mprotect | 4 | unsigned long start | size_t len | unsigned long prot | int pkey | - | - | - |
525 | pkey_alloc | sys_pkey_alloc | 2 | unsigned long flags | unsigned long init_val | - | - | - | - | - |
526 | pkey_free | sys_pkey_free | 1 | int pkey | - | - | - | - | - | - |
527 | rseq | sys_rseq | 4 | struct rseq __user * rseq | u32 rseq_len | int flags | u32 sig | - | - | - |
528 | statfs64 | sys_statfs64 | 3 | const char __user * pathname | size_t sz | struct statfs64 __user * buf | - | - | - | - |
529 | fstatfs64 | sys_fstatfs64 | 3 | unsigned int fd | size_t sz | struct statfs64 __user * buf | - | - | - | - |
530 | getegid | sys_getegid | 0 | - | - | - | - | - | - | - |
531 | geteuid | sys_geteuid | 0 | - | - | - | - | - | - | - |
532 | getppid | sys_getppid | 0 | - | - | - | - | - | - | - |
534 | pidfd_send_signal | sys_pidfd_send_signal | 4 | int pidfd | int sig | siginfo_t __user * info | unsigned int flags | - | - | - |
535 | io_uring_setup | sys_io_uring_setup | 2 | u32 entries | struct io_uring_params __user * params | - | - | - | - | - |
536 | io_uring_enter | sys_io_uring_enter | 6 | unsigned int fd | u32 to_submit | u32 min_complete | u32 flags | const void __user * argp | size_t argsz | - |
537 | io_uring_register | sys_io_uring_register | 4 | unsigned int fd | unsigned int opcode | void __user * arg | unsigned int nr_args | - | - | - |
538 | open_tree | sys_open_tree | 3 | int dfd | const char __user * filename | unsigned flags | - | - | - | - |
539 | move_mount | sys_move_mount | 5 | int from_dfd | const char __user * from_pathname | int to_dfd | const char __user * to_pathname | unsigned int flags | - | - |
540 | fsopen | sys_fsopen | 2 | const char __user * _fs_name | unsigned int flags | - | - | - | - | - |
541 | fsconfig | sys_fsconfig | 5 | int fd | unsigned int cmd | const char __user * _key | const void __user * _value | int aux | - | - |
542 | fsmount | sys_fsmount | 3 | int fs_fd | unsigned int flags | unsigned int attr_flags | - | - | - | - |
543 | fspick | sys_fspick | 3 | int dfd | const char __user * path | unsigned int flags | - | - | - | - |
544 | pidfd_open | sys_pidfd_open | 2 | pid_t pid | unsigned int flags | - | - | - | - | - |
546 | close_range | sys_close_range | 3 | unsigned int fd | unsigned int max_fd | unsigned int flags | - | - | - | - |
547 | openat2 | sys_openat2 | 4 | int dfd | const char __user * filename | struct open_how __user * how | size_t usize | - | - | - |
548 | pidfd_getfd | sys_pidfd_getfd | 3 | int pidfd | int fd | unsigned int flags | - | - | - | - |
549 | faccessat2 | sys_faccessat2 | 4 | int dfd | const char __user * filename | int mode | int flags | - | - | - |
550 | process_madvise | sys_process_madvise | 5 | int pidfd | const struct iovec __user * vec | size_t vlen | int behavior | unsigned int flags | - | - |
551 | epoll_pwait2 | sys_epoll_pwait2 | 6 | int epfd | struct epoll_event __user * events | int maxevents | const struct __kernel_timespec __user * timeout | const sigset_t __user * sigmask | size_t sigsetsize | - |
552 | mount_setattr | sys_mount_setattr | 5 | int dfd | const char __user * path | unsigned int flags | struct mount_attr __user * uattr | size_t usize | - | - |
553 | quotactl_fd | sys_quotactl_fd | 4 | unsigned int fd | unsigned int cmd | qid_t id | void __user * addr | - | - | - |
555 | landlock_add_rule | sys_landlock_add_rule | 4 | const int ruleset_fd | const enum landlock_rule_type rule_type | const void __user *const rule_attr | const __u32 flags | - | - | - |
556 | landlock_restrict_self | sys_landlock_restrict_self | 2 | const int ruleset_fd | const __u32 flags | - | - | - | - | - |
558 | process_mrelease | sys_process_mrelease | 2 | int pidfd | unsigned int flags | - | - | - | - | - |
559 | futex_waitv | sys_futex_waitv | 5 | struct futex_waitv __user * waiters | unsigned int nr_futexes | unsigned int flags | struct __kernel_timespec __user * timeout | clockid_t clockid | - | - |
