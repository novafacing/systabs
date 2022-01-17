
#  mips 32-bit

| Syscall # | Name | Entry Points | # Arguments | arg0 | arg1 | arg2 | arg3 | arg4 | arg5 | arg6 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
0 | read | sys_read | 3 | unsigned int fd | char __user * buf | size_t count | - | - | - | - |
1 | write | sys_write | 3 | unsigned int fd | const char __user * buf | size_t count | - | - | - | - |
2 | open | sys_open | 3 | const char __user * filename | int flags | umode_t mode | - | - | - | - |
3 | close | sys_close | 1 | unsigned int fd | - | - | - | - | - | - |
4 | stat | sys_newstat | 2 | const char __user * filename | struct __old_kernel_stat __user * statbuf | - | - | - | - | - |
4 | newstat | sys_newstat | 2 | const char __user * filename | struct stat __user * statbuf | - | - | - | - | - |
5 | fstat | sys_newfstat | 2 | unsigned int fd | struct __old_kernel_stat __user * statbuf | - | - | - | - | - |
5 | newfstat | sys_newfstat | 2 | unsigned int fd | struct stat __user * statbuf | - | - | - | - | - |
6 | lstat | sys_newlstat | 2 | const char __user * filename | struct __old_kernel_stat __user * statbuf | - | - | - | - | - |
6 | newlstat | sys_newlstat | 2 | const char __user * filename | struct stat __user * statbuf | - | - | - | - | - |
7 | poll | sys_poll | 3 | struct pollfd __user * ufds | unsigned int nfds | int timeout_msecs | - | - | - | - |
8 | lseek | sys_lseek | 3 | unsigned int fd | off_t offset | unsigned int whence | - | - | - | - |
9 | mips_mmap | sys_mips_mmap | 6 | unsigned long addr | unsigned long len | unsigned long prot | unsigned long flags | unsigned long fd | off_t offset | - |
10 | mprotect | sys_mprotect | 3 | unsigned long start | size_t len | unsigned long prot | - | - | - | - |
11 | munmap | sys_munmap | 2 | unsigned long addr | size_t len | - | - | - | - | - |
11 | munmap | sys_munmap | 2 | unsigned long addr | size_t len | - | - | - | - | - |
12 | brk | sys_brk | 1 | unsigned long brk | - | - | - | - | - | - |
12 | brk | sys_brk | 1 | unsigned long brk | - | - | - | - | - | - |
14 | rt_sigprocmask | compat_sys_rt_sigprocmask | 4 | int how | sigset_t __user * nset | sigset_t __user * oset | size_t sigsetsize | - | - | - |
15 | ioctl | compat_sys_ioctl | 3 | unsigned int fd | unsigned int cmd | unsigned long arg | - | - | - | - |
16 | pread64 | sys_pread64 | 4 | unsigned int fd | char __user * buf | size_t count | loff_t pos | - | - | - |
17 | pwrite64 | sys_pwrite64 | 4 | unsigned int fd | const char __user * buf | size_t count | loff_t pos | - | - | - |
18 | readv | sys_readv | 3 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | - | - | - | - |
19 | writev | sys_writev | 3 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | - | - | - | - |
20 | access | sys_access | 2 | const char __user * filename | int mode | - | - | - | - | - |
21 | pipe | sysm_pipe | 1 | int __user * fildes | - | - | - | - | - | - |
23 | sched_yield | sys_sched_yield | 0 | - | - | - | - | - | - | - |
24 | mremap | sys_mremap | 5 | unsigned long addr | unsigned long old_len | unsigned long new_len | unsigned long flags | unsigned long new_addr | - | - |
24 | mremap | sys_mremap | 5 | unsigned long addr | unsigned long old_len | unsigned long new_len | unsigned long flags | unsigned long new_addr | - | - |
25 | msync | sys_msync | 3 | unsigned long start | size_t len | int flags | - | - | - | - |
26 | mincore | sys_mincore | 3 | unsigned long start | size_t len | unsigned char __user * vec | - | - | - | - |
27 | madvise | sys_madvise | 3 | unsigned long start | size_t len_in | int behavior | - | - | - | - |
28 | shmget | sys_shmget | 3 | key_t key | size_t size | int shmflg | - | - | - | - |
29 | shmat | sys_shmat | 3 | int shmid | char __user * shmaddr | int shmflg | - | - | - | - |
30 | shmctl | compat_sys_old_shmctl | 3 | int shmid | int cmd | struct shmid_ds __user * buf | - | - | - | - |
31 | dup | sys_dup | 1 | unsigned int fildes | - | - | - | - | - | - |
32 | dup2 | sys_dup2 | 2 | unsigned int oldfd | unsigned int newfd | - | - | - | - | - |
33 | pause | sys_pause | 0 | - | - | - | - | - | - | - |
34 | nanosleep | sys_nanosleep_time32 | 2 | struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - | - | - |
34 | nanosleep_time32 | sys_nanosleep_time32 | 2 | struct old_timespec32 __user * rqtp | struct old_timespec32 __user * rmtp | - | - | - | - | - |
35 | getitimer | compat_sys_getitimer | 2 | int which | struct __kernel_old_itimerval __user * value | - | - | - | - | - |
36 | setitimer | compat_sys_setitimer | 3 | int which | struct __kernel_old_itimerval __user * value | struct __kernel_old_itimerval __user * ovalue | - | - | - | - |
37 | alarm | sys_alarm | 1 | unsigned int seconds | - | - | - | - | - | - |
38 | getpid | sys_getpid | 0 | - | - | - | - | - | - | - |
39 | sendfile | compat_sys_sendfile | 4 | int out_fd | int in_fd | off_t __user * offset | size_t count | - | - | - |
40 | socket | sys_socket | 3 | int family | int type | int protocol | - | - | - | - |
41 | connect | sys_connect | 3 | int fd | struct sockaddr __user * uservaddr | int addrlen | - | - | - | - |
42 | accept | sys_accept | 3 | int fd | struct sockaddr __user * upeer_sockaddr | int __user * upeer_addrlen | - | - | - | - |
43 | sendto | sys_sendto | 6 | int fd | void __user * buff | size_t len | unsigned int flags | struct sockaddr __user * addr | int addr_len | - |
44 | recvfrom | compat_sys_recvfrom | 6 | int fd | void __user * ubuf | size_t size | unsigned int flags | struct sockaddr __user * addr | int __user * addr_len | - |
45 | sendmsg | compat_sys_sendmsg | 3 | int fd | struct user_msghdr __user * msg | unsigned int flags | - | - | - | - |
46 | recvmsg | compat_sys_recvmsg | 3 | int fd | struct user_msghdr __user * msg | unsigned int flags | - | - | - | - |
47 | shutdown | sys_shutdown | 2 | int fd | int how | - | - | - | - | - |
48 | bind | sys_bind | 3 | int fd | struct sockaddr __user * umyaddr | int addrlen | - | - | - | - |
49 | listen | sys_listen | 2 | int fd | int backlog | - | - | - | - | - |
50 | getsockname | sys_getsockname | 3 | int fd | struct sockaddr __user * usockaddr | int __user * usockaddr_len | - | - | - | - |
51 | getpeername | sys_getpeername | 3 | int fd | struct sockaddr __user * usockaddr | int __user * usockaddr_len | - | - | - | - |
52 | socketpair | sys_socketpair | 4 | int family | int type | int protocol | int __user * usockvec | - | - | - |
53 | setsockopt | sys_setsockopt | 5 | int fd | int level | int optname | char __user * optval | int optlen | - | - |
54 | getsockopt | sys_getsockopt | 5 | int fd | int level | int optname | char __user * optval | int __user * optlen | - | - |
55 | clone | __sys_clone | 5 | unsigned long clone_flags | unsigned long newsp | int __user * parent_tidptr | unsigned long tls | int __user * child_tidptr | - | - |
55 | clone | __sys_clone | 5 | unsigned long newsp | unsigned long clone_flags | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - | - |
55 | clone | __sys_clone | 6 | unsigned long clone_flags | unsigned long newsp | int stack_size | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - |
55 | clone | __sys_clone | 5 | unsigned long clone_flags | unsigned long newsp | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - | - |
56 | fork | __sys_fork | 0 | - | - | - | - | - | - | - |
57 | execve | compat_sys_execve | 3 | const char __user * filename | const char __user *const __user * argv | const char __user *const __user * envp | - | - | - | - |
58 | exit | sys_exit | 1 | int error_code | - | - | - | - | - | - |
60 | kill | sys_kill | 2 | pid_t pid | int sig | - | - | - | - | - |
61 | newuname | sys_newuname | 1 | struct new_utsname __user * name | - | - | - | - | - | - |
61 | uname | sys_newuname | 1 | struct old_utsname __user * name | - | - | - | - | - | - |
62 | semget | sys_semget | 3 | key_t key | int nsems | int semflg | - | - | - | - |
63 | semop | sys_semop | 3 | int semid | struct sembuf __user * tsops | unsigned nsops | - | - | - | - |
64 | semctl | compat_sys_old_semctl | 4 | int semid | int semnum | int cmd | unsigned long arg | - | - | - |
65 | shmdt | sys_shmdt | 1 | char __user * shmaddr | - | - | - | - | - | - |
66 | msgget | sys_msgget | 2 | key_t key | int msgflg | - | - | - | - | - |
67 | msgsnd | compat_sys_msgsnd | 4 | int msqid | struct msgbuf __user * msgp | size_t msgsz | int msgflg | - | - | - |
68 | msgrcv | compat_sys_msgrcv | 5 | int msqid | struct msgbuf __user * msgp | size_t msgsz | long msgtyp | int msgflg | - | - |
69 | msgctl | compat_sys_old_msgctl | 3 | int msqid | int cmd | struct msqid_ds __user * buf | - | - | - | - |
70 | fcntl | compat_sys_fcntl | 3 | unsigned int fd | unsigned int cmd | unsigned long arg | - | - | - | - |
71 | flock | sys_flock | 2 | unsigned int fd | unsigned int cmd | - | - | - | - | - |
72 | fsync | sys_fsync | 1 | unsigned int fd | - | - | - | - | - | - |
73 | fdatasync | sys_fdatasync | 1 | unsigned int fd | - | - | - | - | - | - |
74 | truncate | sys_truncate | 2 | const char __user * path | long length | - | - | - | - | - |
75 | ftruncate | sys_ftruncate | 2 | unsigned int fd | unsigned long length | - | - | - | - | - |
76 | getdents | compat_sys_getdents | 3 | unsigned int fd | struct linux_dirent __user * dirent | unsigned int count | - | - | - | - |
77 | getcwd | sys_getcwd | 2 | char __user * buf | unsigned long size | - | - | - | - | - |
78 | chdir | sys_chdir | 1 | const char __user * filename | - | - | - | - | - | - |
79 | fchdir | sys_fchdir | 1 | unsigned int fd | - | - | - | - | - | - |
80 | rename | sys_rename | 2 | const char __user * oldname | const char __user * newname | - | - | - | - | - |
81 | mkdir | sys_mkdir | 2 | const char __user * pathname | umode_t mode | - | - | - | - | - |
82 | rmdir | sys_rmdir | 1 | const char __user * pathname | - | - | - | - | - | - |
83 | creat | sys_creat | 2 | const char __user * pathname | umode_t mode | - | - | - | - | - |
84 | link | sys_link | 2 | const char __user * oldname | const char __user * newname | - | - | - | - | - |
85 | unlink | sys_unlink | 1 | const char __user * pathname | - | - | - | - | - | - |
86 | symlink | sys_symlink | 2 | const char __user * oldname | const char __user * newname | - | - | - | - | - |
87 | readlink | sys_readlink | 3 | const char __user * path | char __user * buf | int bufsiz | - | - | - | - |
88 | chmod | sys_chmod | 2 | const char __user * filename | umode_t mode | - | - | - | - | - |
89 | fchmod | sys_fchmod | 2 | unsigned int fd | umode_t mode | - | - | - | - | - |
90 | chown | sys_chown | 3 | const char __user * filename | uid_t user | gid_t group | - | - | - | - |
91 | fchown | sys_fchown | 3 | unsigned int fd | uid_t user | gid_t group | - | - | - | - |
92 | lchown | sys_lchown | 3 | const char __user * filename | uid_t user | gid_t group | - | - | - | - |
94 | gettimeofday | compat_sys_gettimeofday | 2 | struct __kernel_old_timeval __user * tv | struct timezone __user * tz | - | - | - | - | - |
95 | getrlimit | compat_sys_getrlimit | 2 | unsigned int resource | struct rlimit __user * rlim | - | - | - | - | - |
96 | getrusage | compat_sys_getrusage | 2 | int who | struct rusage __user * ru | - | - | - | - | - |
98 | times | compat_sys_times | 1 | struct tms __user * tbuf | - | - | - | - | - | - |
99 | ptrace | compat_sys_ptrace | 4 | long request | long pid | unsigned long addr | unsigned long data | - | - | - |
100 | getuid | sys_getuid | 0 | - | - | - | - | - | - | - |
101 | syslog | sys_syslog | 3 | int type | char __user * buf | int len | - | - | - | - |
102 | getgid | sys_getgid | 0 | - | - | - | - | - | - | - |
103 | setuid | sys_setuid | 1 | uid_t uid | - | - | - | - | - | - |
104 | setgid | sys_setgid | 1 | gid_t gid | - | - | - | - | - | - |
105 | geteuid | sys_geteuid | 0 | - | - | - | - | - | - | - |
106 | getegid | sys_getegid | 0 | - | - | - | - | - | - | - |
107 | setpgid | sys_setpgid | 2 | pid_t pid | pid_t pgid | - | - | - | - | - |
108 | getppid | sys_getppid | 0 | - | - | - | - | - | - | - |
109 | getpgrp | sys_getpgrp | 0 | - | - | - | - | - | - | - |
110 | setsid | sys_setsid | 0 | - | - | - | - | - | - | - |
111 | setreuid | sys_setreuid | 2 | uid_t ruid | uid_t euid | - | - | - | - | - |
112 | setregid | sys_setregid | 2 | gid_t rgid | gid_t egid | - | - | - | - | - |
113 | getgroups | sys_getgroups | 2 | int gidsetsize | gid_t __user * grouplist | - | - | - | - | - |
114 | setgroups | sys_setgroups | 2 | int gidsetsize | gid_t __user * grouplist | - | - | - | - | - |
115 | setresuid | sys_setresuid | 3 | uid_t ruid | uid_t euid | uid_t suid | - | - | - | - |
116 | getresuid | sys_getresuid | 3 | uid_t __user * ruidp | uid_t __user * euidp | uid_t __user * suidp | - | - | - | - |
117 | setresgid | sys_setresgid | 3 | gid_t rgid | gid_t egid | gid_t sgid | - | - | - | - |
118 | getresgid | sys_getresgid | 3 | gid_t __user * rgidp | gid_t __user * egidp | gid_t __user * sgidp | - | - | - | - |
119 | getpgid | sys_getpgid | 1 | pid_t pid | - | - | - | - | - | - |
120 | setfsuid | sys_setfsuid | 1 | uid_t uid | - | - | - | - | - | - |
121 | setfsgid | sys_setfsgid | 1 | gid_t gid | - | - | - | - | - | - |
122 | getsid | sys_getsid | 1 | pid_t pid | - | - | - | - | - | - |
123 | capget | sys_capget | 2 | cap_user_header_t header | cap_user_data_t dataptr | - | - | - | - | - |
124 | capset | sys_capset | 2 | cap_user_header_t header | const cap_user_data_t data | - | - | - | - | - |
125 | rt_sigpending | compat_sys_rt_sigpending | 2 | sigset_t __user * uset | size_t sigsetsize | - | - | - | - | - |
126 | rt_sigtimedwait | compat_sys_rt_sigtimedwait_time32 | 4 | const sigset_t __user * uthese | siginfo_t __user * uinfo | const struct __kernel_timespec __user * uts | size_t sigsetsize | - | - | - |
127 | rt_sigqueueinfo | compat_sys_rt_sigqueueinfo | 3 | pid_t pid | int sig | siginfo_t __user * uinfo | - | - | - | - |
128 | rt_sigsuspend | compat_sys_rt_sigsuspend | 2 | sigset_t __user * unewset | size_t sigsetsize | - | - | - | - | - |
129 | sigaltstack | compat_sys_sigaltstack | 2 | const stack_t __user * uss | stack_t __user * uoss | - | - | - | - | - |
130 | utime | sys_utime32 | 2 | char __user * filename | struct utimbuf __user * times | - | - | - | - | - |
130 | utime32 | sys_utime32 | 2 | const char __user * filename | struct old_utimbuf32 __user * t | - | - | - | - | - |
131 | mknod | sys_mknod | 3 | const char __user * filename | umode_t mode | unsigned dev | - | - | - | - |
132 | personality | sys_32_personality | 1 | unsigned int personality | - | - | - | - | - | - |
133 | ustat | compat_sys_ustat | 2 | unsigned dev | struct ustat __user * ubuf | - | - | - | - | - |
134 | statfs | compat_sys_statfs | 2 | const char __user * pathname | struct statfs __user * buf | - | - | - | - | - |
135 | fstatfs | compat_sys_fstatfs | 2 | unsigned int fd | struct statfs __user * buf | - | - | - | - | - |
136 | sysfs | sys_sysfs | 3 | int option | unsigned long arg1 | unsigned long arg2 | - | - | - | - |
137 | getpriority | sys_getpriority | 2 | int which | int who | - | - | - | - | - |
138 | setpriority | sys_setpriority | 3 | int which | int who | int niceval | - | - | - | - |
139 | sched_setparam | sys_sched_setparam | 2 | pid_t pid | struct sched_param __user * param | - | - | - | - | - |
140 | sched_getparam | sys_sched_getparam | 2 | pid_t pid | struct sched_param __user * param | - | - | - | - | - |
141 | sched_setscheduler | sys_sched_setscheduler | 3 | pid_t pid | int policy | struct sched_param __user * param | - | - | - | - |
142 | sched_getscheduler | sys_sched_getscheduler | 1 | pid_t pid | - | - | - | - | - | - |
143 | sched_get_priority_max | sys_sched_get_priority_max | 1 | int policy | - | - | - | - | - | - |
144 | sched_get_priority_min | sys_sched_get_priority_min | 1 | int policy | - | - | - | - | - | - |
145 | sched_rr_get_interval | sys_sched_rr_get_interval_time32 | 2 | pid_t pid | struct __kernel_timespec __user * interval | - | - | - | - | - |
145 | sched_rr_get_interval_time32 | sys_sched_rr_get_interval_time32 | 2 | pid_t pid | struct old_timespec32 __user * interval | - | - | - | - | - |
146 | mlock | sys_mlock | 2 | unsigned long start | size_t len | - | - | - | - | - |
147 | munlock | sys_munlock | 2 | unsigned long start | size_t len | - | - | - | - | - |
148 | mlockall | sys_mlockall | 1 | int flags | - | - | - | - | - | - |
149 | munlockall | sys_munlockall | 0 | - | - | - | - | - | - | - |
150 | vhangup | sys_vhangup | 0 | - | - | - | - | - | - | - |
151 | pivot_root | sys_pivot_root | 2 | const char __user * new_root | const char __user * put_old | - | - | - | - | - |
154 | adjtimex | sys_adjtimex_time32 | 1 | struct __kernel_timex __user * txc_p | - | - | - | - | - | - |
154 | adjtimex_time32 | sys_adjtimex_time32 | 1 | struct old_timex32 __user * utp | - | - | - | - | - | - |
155 | setrlimit | compat_sys_setrlimit | 2 | unsigned int resource | struct rlimit __user * rlim | - | - | - | - | - |
156 | chroot | sys_chroot | 1 | const char __user * filename | - | - | - | - | - | - |
157 | sync | sys_sync | 0 | - | - | - | - | - | - | - |
158 | acct | sys_acct | 1 | const char __user * name | - | - | - | - | - | - |
159 | settimeofday | compat_sys_settimeofday | 2 | struct __kernel_old_timeval __user * tv | struct timezone __user * tz | - | - | - | - | - |
160 | mount | sys_mount | 5 | char __user * dev_name | char __user * dir_name | char __user * type | unsigned long flags | void __user * data | - | - |
161 | umount | sys_umount | 2 | char __user * name | int flags | - | - | - | - | - |
162 | swapon | sys_swapon | 2 | const char __user * specialfile | int swap_flags | - | - | - | - | - |
163 | swapoff | sys_swapoff | 1 | const char __user * specialfile | - | - | - | - | - | - |
164 | reboot | sys_reboot | 4 | int magic1 | int magic2 | unsigned int cmd | void __user * arg | - | - | - |
165 | sethostname | sys_sethostname | 2 | char __user * name | int len | - | - | - | - | - |
166 | setdomainname | sys_setdomainname | 2 | char __user * name | int len | - | - | - | - | - |
168 | init_module | sys_init_module | 3 | void __user * umod | unsigned long len | const char __user * uargs | - | - | - | - |
169 | delete_module | sys_delete_module | 2 | const char __user * name_user | unsigned int flags | - | - | - | - | - |
172 | quotactl | sys_quotactl | 4 | unsigned int cmd | const char __user * special | qid_t id | void __user * addr | - | - | - |
178 | gettid | sys_gettid | 0 | - | - | - | - | - | - | - |
179 | readahead | sys_readahead | 3 | int fd | loff_t offset | size_t count | - | - | - | - |
180 | setxattr | sys_setxattr | 5 | const char __user * pathname | const char __user * name | const void __user * value | size_t size | int flags | - | - |
181 | lsetxattr | sys_lsetxattr | 5 | const char __user * pathname | const char __user * name | const void __user * value | size_t size | int flags | - | - |
182 | fsetxattr | sys_fsetxattr | 5 | int fd | const char __user * name | const void __user * value | size_t size | int flags | - | - |
183 | getxattr | sys_getxattr | 4 | const char __user * pathname | const char __user * name | void __user * value | size_t size | - | - | - |
184 | lgetxattr | sys_lgetxattr | 4 | const char __user * pathname | const char __user * name | void __user * value | size_t size | - | - | - |
185 | fgetxattr | sys_fgetxattr | 4 | int fd | const char __user * name | void __user * value | size_t size | - | - | - |
186 | listxattr | sys_listxattr | 3 | const char __user * pathname | char __user * list | size_t size | - | - | - | - |
187 | llistxattr | sys_llistxattr | 3 | const char __user * pathname | char __user * list | size_t size | - | - | - | - |
188 | flistxattr | sys_flistxattr | 3 | int fd | char __user * list | size_t size | - | - | - | - |
189 | removexattr | sys_removexattr | 2 | const char __user * pathname | const char __user * name | - | - | - | - | - |
190 | lremovexattr | sys_lremovexattr | 2 | const char __user * pathname | const char __user * name | - | - | - | - | - |
191 | fremovexattr | sys_fremovexattr | 2 | int fd | const char __user * name | - | - | - | - | - |
192 | tkill | sys_tkill | 2 | pid_t pid | int sig | - | - | - | - | - |
194 | futex | sys_futex_time32 | 6 | u32 __user * uaddr | int op | u32 val | const struct __kernel_timespec __user * utime | u32 __user * uaddr2 | u32 val3 | - |
194 | futex_time32 | sys_futex_time32 | 6 | u32 __user * uaddr | int op | u32 val | const struct old_timespec32 __user * utime | u32 __user * uaddr2 | u32 val3 | - |
195 | sched_setaffinity | compat_sys_sched_setaffinity | 3 | pid_t pid | unsigned int len | unsigned long __user * user_mask_ptr | - | - | - | - |
196 | sched_getaffinity | compat_sys_sched_getaffinity | 3 | pid_t pid | unsigned int len | unsigned long __user * user_mask_ptr | - | - | - | - |
197 | cacheflush | sys_cacheflush | 3 | unsigned long addr | unsigned long bytes | unsigned int cache | - | - | - | - |
198 | cachectl | sys_cachectl | 3 | char * addr | int nbytes | int op | - | - | - | - |
199 | sysmips | __sys_sysmips | 3 | long cmd | long arg1 | long arg2 | - | - | - | - |
200 | io_setup | compat_sys_io_setup | 2 | unsigned nr_events | aio_context_t __user * ctxp | - | - | - | - | - |
201 | io_destroy | sys_io_destroy | 1 | aio_context_t ctx | - | - | - | - | - | - |
202 | io_getevents | sys_io_getevents_time32 | 5 | aio_context_t ctx_id | long min_nr | long nr | struct io_event __user * events | struct __kernel_timespec __user * timeout | - | - |
202 | io_getevents_time32 | sys_io_getevents_time32 | 5 | __u32 ctx_id | __s32 min_nr | __s32 nr | struct io_event __user * events | struct old_timespec32 __user * timeout | - | - |
203 | io_submit | compat_sys_io_submit | 3 | aio_context_t ctx_id | long nr | struct iocb __user * __user * iocbpp | - | - | - | - |
204 | io_cancel | sys_io_cancel | 3 | aio_context_t ctx_id | struct iocb __user * iocb | struct io_event __user * result | - | - | - | - |
205 | exit_group | sys_exit_group | 1 | int error_code | - | - | - | - | - | - |
207 | epoll_create | sys_epoll_create | 1 | int size | - | - | - | - | - | - |
208 | epoll_ctl | sys_epoll_ctl | 4 | int epfd | int op | int fd | struct epoll_event __user * event | - | - | - |
209 | epoll_wait | sys_epoll_wait | 4 | int epfd | struct epoll_event __user * events | int maxevents | int timeout | - | - | - |
210 | remap_file_pages | sys_remap_file_pages | 5 | unsigned long start | unsigned long size | unsigned long prot | unsigned long pgoff | unsigned long flags | - | - |
212 | fcntl64 | compat_sys_fcntl64 | 3 | unsigned int fd | unsigned int cmd | unsigned long arg | - | - | - | - |
213 | set_tid_address | sys_set_tid_address | 1 | int __user * tidptr | - | - | - | - | - | - |
214 | restart_syscall | sys_restart_syscall | 0 | - | - | - | - | - | - | - |
215 | semtimedop | sys_semtimedop_time32 | 4 | int semid | struct sembuf __user * tsops | unsigned int nsops | const struct __kernel_timespec __user * timeout | - | - | - |
215 | semtimedop_time32 | sys_semtimedop_time32 | 4 | int semid | struct sembuf __user * tsems | unsigned int nsops | const struct old_timespec32 __user * timeout | - | - | - |
216 | fadvise64_64 | sys_fadvise64_64 | 4 | int fd | loff_t offset | loff_t len | int advice | - | - | - |
216 | fadvise64 | sys_fadvise64_64 | 4 | int fd | loff_t offset | size_t len | int advice | - | - | - |
217 | statfs64 | compat_sys_statfs64 | 3 | const char __user * pathname | size_t sz | struct statfs64 __user * buf | - | - | - | - |
218 | fstatfs64 | compat_sys_fstatfs64 | 3 | unsigned int fd | size_t sz | struct statfs64 __user * buf | - | - | - | - |
219 | sendfile64 | sys_sendfile64 | 4 | int out_fd | int in_fd | loff_t __user * offset | size_t count | - | - | - |
220 | timer_create | compat_sys_timer_create | 3 | const clockid_t which_clock | struct sigevent __user * timer_event_spec | timer_t __user * created_timer_id | - | - | - | - |
221 | timer_settime | sys_timer_settime32 | 4 | timer_t timer_id | int flags | const struct __kernel_itimerspec __user * new_setting | struct __kernel_itimerspec __user * old_setting | - | - | - |
221 | timer_settime32 | sys_timer_settime32 | 4 | timer_t timer_id | int flags | struct old_itimerspec32 __user * new | struct old_itimerspec32 __user * old | - | - | - |
222 | timer_gettime | sys_timer_gettime32 | 2 | timer_t timer_id | struct __kernel_itimerspec __user * setting | - | - | - | - | - |
222 | timer_gettime32 | sys_timer_gettime32 | 2 | timer_t timer_id | struct old_itimerspec32 __user * setting | - | - | - | - | - |
223 | timer_getoverrun | sys_timer_getoverrun | 1 | timer_t timer_id | - | - | - | - | - | - |
224 | timer_delete | sys_timer_delete | 1 | timer_t timer_id | - | - | - | - | - | - |
225 | clock_settime | sys_clock_settime32 | 2 | const clockid_t which_clock | const struct __kernel_timespec __user * tp | - | - | - | - | - |
225 | clock_settime32 | sys_clock_settime32 | 2 | const clockid_t which_clock | struct old_timespec32 __user * tp | - | - | - | - | - |
225 | clock_settime | sys_clock_settime32 | 2 | const clockid_t which_clock | const struct __kernel_timespec __user * tp | - | - | - | - | - |
225 | clock_settime32 | sys_clock_settime32 | 2 | clockid_t which_clock | struct old_timespec32 __user * tp | - | - | - | - | - |
226 | clock_gettime | sys_clock_gettime32 | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
226 | clock_gettime32 | sys_clock_gettime32 | 2 | clockid_t which_clock | struct old_timespec32 __user * tp | - | - | - | - | - |
226 | clock_gettime | sys_clock_gettime32 | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
226 | clock_gettime32 | sys_clock_gettime32 | 2 | clockid_t which_clock | struct old_timespec32 __user * tp | - | - | - | - | - |
227 | clock_getres | sys_clock_getres_time32 | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
227 | clock_getres_time32 | sys_clock_getres_time32 | 2 | clockid_t which_clock | struct old_timespec32 __user * tp | - | - | - | - | - |
227 | clock_getres | sys_clock_getres_time32 | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
227 | clock_getres_time32 | sys_clock_getres_time32 | 2 | clockid_t which_clock | struct old_timespec32 __user * tp | - | - | - | - | - |
228 | clock_nanosleep | sys_clock_nanosleep_time32 | 4 | const clockid_t which_clock | int flags | const struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - |
228 | clock_nanosleep_time32 | sys_clock_nanosleep_time32 | 4 | clockid_t which_clock | int flags | struct old_timespec32 __user * rqtp | struct old_timespec32 __user * rmtp | - | - | - |
228 | clock_nanosleep | sys_clock_nanosleep_time32 | 4 | const clockid_t which_clock | int flags | const struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - |
228 | clock_nanosleep_time32 | sys_clock_nanosleep_time32 | 4 | clockid_t which_clock | int flags | struct old_timespec32 __user * rqtp | struct old_timespec32 __user * rmtp | - | - | - |
229 | tgkill | sys_tgkill | 3 | pid_t tgid | pid_t pid | int sig | - | - | - | - |
230 | utimes | sys_utimes_time32 | 2 | char __user * filename | struct __kernel_old_timeval __user * utimes | - | - | - | - | - |
230 | utimes_time32 | sys_utimes_time32 | 2 | const char __user * filename | struct old_timeval32 __user * t | - | - | - | - | - |
231 | mbind | sys_mbind | 6 | unsigned long start | unsigned long len | unsigned long mode | const unsigned long __user * nmask | unsigned long maxnode | unsigned int flags | - |
232 | get_mempolicy | sys_get_mempolicy | 5 | int __user * policy | unsigned long __user * nmask | unsigned long maxnode | unsigned long addr | unsigned long flags | - | - |
233 | set_mempolicy | sys_set_mempolicy | 3 | int mode | const unsigned long __user * nmask | unsigned long maxnode | - | - | - | - |
234 | mq_open | compat_sys_mq_open | 4 | const char __user * u_name | int oflag | umode_t mode | struct mq_attr __user * u_attr | - | - | - |
235 | mq_unlink | sys_mq_unlink | 1 | const char __user * u_name | - | - | - | - | - | - |
236 | mq_timedsend | sys_mq_timedsend_time32 | 5 | mqd_t mqdes | const char __user * u_msg_ptr | size_t msg_len | unsigned int msg_prio | const struct __kernel_timespec __user * u_abs_timeout | - | - |
236 | mq_timedsend_time32 | sys_mq_timedsend_time32 | 5 | mqd_t mqdes | const char __user * u_msg_ptr | unsigned int msg_len | unsigned int msg_prio | const struct old_timespec32 __user * u_abs_timeout | - | - |
237 | mq_timedreceive | sys_mq_timedreceive_time32 | 5 | mqd_t mqdes | char __user * u_msg_ptr | size_t msg_len | unsigned int __user * u_msg_prio | const struct __kernel_timespec __user * u_abs_timeout | - | - |
237 | mq_timedreceive_time32 | sys_mq_timedreceive_time32 | 5 | mqd_t mqdes | char __user * u_msg_ptr | unsigned int msg_len | unsigned int __user * u_msg_prio | const struct old_timespec32 __user * u_abs_timeout | - | - |
243 | add_key | sys_add_key | 5 | const char __user * _type | const char __user * _description | const void __user * _payload | size_t plen | key_serial_t ringid | - | - |
244 | request_key | sys_request_key | 4 | const char __user * _type | const char __user * _description | const char __user * _callout_info | key_serial_t destringid | - | - | - |
245 | keyctl | compat_sys_keyctl | 5 | int option | unsigned long arg2 | unsigned long arg3 | unsigned long arg4 | unsigned long arg5 | - | - |
246 | set_thread_area | sys_set_thread_area | 1 | unsigned long addr | - | - | - | - | - | - |
247 | inotify_init | sys_inotify_init | 0 | - | - | - | - | - | - | - |
248 | inotify_add_watch | sys_inotify_add_watch | 3 | int fd | const char __user * pathname | u32 mask | - | - | - | - |
249 | inotify_rm_watch | sys_inotify_rm_watch | 2 | int fd | __s32 wd | - | - | - | - | - |
250 | migrate_pages | sys_migrate_pages | 4 | pid_t pid | unsigned long maxnode | const unsigned long __user * old_nodes | const unsigned long __user * new_nodes | - | - | - |
251 | openat | sys_openat | 4 | int dfd | const char __user * filename | int flags | umode_t mode | - | - | - |
252 | mkdirat | sys_mkdirat | 3 | int dfd | const char __user * pathname | umode_t mode | - | - | - | - |
253 | mknodat | sys_mknodat | 4 | int dfd | const char __user * filename | umode_t mode | unsigned int dev | - | - | - |
254 | fchownat | sys_fchownat | 5 | int dfd | const char __user * filename | uid_t user | gid_t group | int flag | - | - |
255 | futimesat | sys_futimesat_time32 | 3 | int dfd | const char __user * filename | struct __kernel_old_timeval __user * utimes | - | - | - | - |
255 | futimesat_time32 | sys_futimesat_time32 | 3 | unsigned int dfd | const char __user * filename | struct old_timeval32 __user * t | - | - | - | - |
256 | newfstatat | sys_newfstatat | 4 | int dfd | const char __user * filename | struct stat __user * statbuf | int flag | - | - | - |
257 | unlinkat | sys_unlinkat | 3 | int dfd | const char __user * pathname | int flag | - | - | - | - |
258 | renameat | sys_renameat | 4 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | - | - | - |
259 | linkat | sys_linkat | 5 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | int flags | - | - |
260 | symlinkat | sys_symlinkat | 3 | const char __user * oldname | int newdfd | const char __user * newname | - | - | - | - |
261 | readlinkat | sys_readlinkat | 4 | int dfd | const char __user * pathname | char __user * buf | int bufsiz | - | - | - |
262 | fchmodat | sys_fchmodat | 3 | int dfd | const char __user * filename | umode_t mode | - | - | - | - |
263 | faccessat | sys_faccessat | 3 | int dfd | const char __user * filename | int mode | - | - | - | - |
264 | pselect6 | compat_sys_pselect6_time32 | 6 | int n | fd_set __user * inp | fd_set __user * outp | fd_set __user * exp | struct __kernel_timespec __user * tsp | void __user * sig | - |
265 | ppoll | compat_sys_ppoll_time32 | 5 | struct pollfd __user * ufds | unsigned int nfds | struct __kernel_timespec __user * tsp | const sigset_t __user * sigmask | size_t sigsetsize | - | - |
266 | unshare | sys_unshare | 1 | unsigned long unshare_flags | - | - | - | - | - | - |
267 | splice | sys_splice | 6 | int fd_in | loff_t __user * off_in | int fd_out | loff_t __user * off_out | size_t len | unsigned int flags | - |
268 | sync_file_range | sys_sync_file_range | 4 | int fd | loff_t offset | loff_t nbytes | unsigned int flags | - | - | - |
269 | tee | sys_tee | 4 | int fdin | int fdout | size_t len | unsigned int flags | - | - | - |
270 | vmsplice | sys_vmsplice | 4 | int fd | const struct iovec __user * uiov | unsigned long nr_segs | unsigned int flags | - | - | - |
271 | move_pages | sys_move_pages | 6 | pid_t pid | unsigned long nr_pages | const void __user * __user * pages | const int __user * nodes | int __user * status | int flags | - |
272 | set_robust_list | compat_sys_set_robust_list | 2 | struct robust_list_head __user * head | size_t len | - | - | - | - | - |
273 | get_robust_list | compat_sys_get_robust_list | 3 | int pid | struct robust_list_head __user * __user * head_ptr | size_t __user * len_ptr | - | - | - | - |
274 | kexec_load | compat_sys_kexec_load | 4 | unsigned long entry | unsigned long nr_segments | struct kexec_segment __user * segments | unsigned long flags | - | - | - |
276 | epoll_pwait | compat_sys_epoll_pwait | 6 | int epfd | struct epoll_event __user * events | int maxevents | int timeout | const sigset_t __user * sigmask | size_t sigsetsize | - |
277 | ioprio_set | sys_ioprio_set | 3 | int which | int who | int ioprio | - | - | - | - |
278 | ioprio_get | sys_ioprio_get | 2 | int which | int who | - | - | - | - | - |
279 | utimensat | sys_utimensat_time32 | 4 | int dfd | const char __user * filename | struct __kernel_timespec __user * utimes | int flags | - | - | - |
279 | utimensat_time32 | sys_utimensat_time32 | 4 | unsigned int dfd | const char __user * filename | struct old_timespec32 __user * t | int flags | - | - | - |
280 | signalfd | compat_sys_signalfd | 3 | int ufd | sigset_t __user * user_mask | size_t sizemask | - | - | - | - |
282 | eventfd | sys_eventfd | 1 | unsigned int count | - | - | - | - | - | - |
283 | fallocate | sys_fallocate | 4 | int fd | int mode | loff_t offset | loff_t len | - | - | - |
284 | timerfd_create | sys_timerfd_create | 2 | int clockid | int flags | - | - | - | - | - |
285 | timerfd_gettime | sys_timerfd_gettime32 | 2 | int ufd | struct __kernel_itimerspec __user * otmr | - | - | - | - | - |
285 | timerfd_gettime32 | sys_timerfd_gettime32 | 2 | int ufd | struct old_itimerspec32 __user * otmr | - | - | - | - | - |
286 | timerfd_settime | sys_timerfd_settime32 | 4 | int ufd | int flags | const struct __kernel_itimerspec __user * utmr | struct __kernel_itimerspec __user * otmr | - | - | - |
286 | timerfd_settime32 | sys_timerfd_settime32 | 4 | int ufd | int flags | const struct old_itimerspec32 __user * utmr | struct old_itimerspec32 __user * otmr | - | - | - |
287 | signalfd4 | compat_sys_signalfd4 | 4 | int ufd | sigset_t __user * user_mask | size_t sizemask | int flags | - | - | - |
288 | eventfd2 | sys_eventfd2 | 2 | unsigned int count | int flags | - | - | - | - | - |
289 | epoll_create1 | sys_epoll_create1 | 1 | int flags | - | - | - | - | - | - |
290 | dup3 | sys_dup3 | 3 | unsigned int oldfd | unsigned int newfd | int flags | - | - | - | - |
291 | pipe2 | sys_pipe2 | 2 | int __user * fildes | int flags | - | - | - | - | - |
292 | inotify_init1 | sys_inotify_init1 | 1 | int flags | - | - | - | - | - | - |
293 | preadv | compat_sys_preadv | 5 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | - | - |
294 | pwritev | compat_sys_pwritev | 5 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | - | - |
295 | rt_tgsigqueueinfo | compat_sys_rt_tgsigqueueinfo | 4 | pid_t tgid | pid_t pid | int sig | siginfo_t __user * uinfo | - | - | - |
296 | perf_event_open | sys_perf_event_open | 5 | struct perf_event_attr __user * attr_uptr | pid_t pid | int cpu | int group_fd | unsigned long flags | - | - |
297 | accept4 | sys_accept4 | 4 | int fd | struct sockaddr __user * upeer_sockaddr | int __user * upeer_addrlen | int flags | - | - | - |
298 | recvmmsg | compat_sys_recvmmsg_time32 | 5 | int fd | struct mmsghdr __user * mmsg | unsigned int vlen | unsigned int flags | struct __kernel_timespec __user * timeout | - | - |
299 | getdents64 | sys_getdents64 | 3 | unsigned int fd | struct linux_dirent64 __user * dirent | unsigned int count | - | - | - | - |
300 | fanotify_init | sys_fanotify_init | 2 | unsigned int flags | unsigned int event_f_flags | - | - | - | - | - |
301 | fanotify_mark | sys_fanotify_mark | 5 | int fanotify_fd | unsigned int flags | __u64 mask | int dfd | const char __user * pathname | - | - |
302 | prlimit64 | sys_prlimit64 | 4 | pid_t pid | unsigned int resource | const struct rlimit64 __user * new_rlim | struct rlimit64 __user * old_rlim | - | - | - |
303 | name_to_handle_at | sys_name_to_handle_at | 5 | int dfd | const char __user * name | struct file_handle __user * handle | int __user * mnt_id | int flag | - | - |
304 | open_by_handle_at | sys_open_by_handle_at | 3 | int mountdirfd | struct file_handle __user * handle | int flags | - | - | - | - |
305 | clock_adjtime | sys_clock_adjtime32 | 2 | const clockid_t which_clock | struct __kernel_timex __user * utx | - | - | - | - | - |
305 | clock_adjtime32 | sys_clock_adjtime32 | 2 | clockid_t which_clock | struct old_timex32 __user * utp | - | - | - | - | - |
306 | syncfs | sys_syncfs | 1 | int fd | - | - | - | - | - | - |
307 | sendmmsg | compat_sys_sendmmsg | 4 | int fd | struct mmsghdr __user * mmsg | unsigned int vlen | unsigned int flags | - | - | - |
308 | setns | sys_setns | 2 | int fd | int flags | - | - | - | - | - |
309 | process_vm_readv | sys_process_vm_readv | 6 | pid_t pid | const struct iovec __user * lvec | unsigned long liovcnt | const struct iovec __user * rvec | unsigned long riovcnt | unsigned long flags | - |
310 | process_vm_writev | sys_process_vm_writev | 6 | pid_t pid | const struct iovec __user * lvec | unsigned long liovcnt | const struct iovec __user * rvec | unsigned long riovcnt | unsigned long flags | - |
311 | kcmp | sys_kcmp | 5 | pid_t pid1 | pid_t pid2 | int type | unsigned long idx1 | unsigned long idx2 | - | - |
312 | finit_module | sys_finit_module | 3 | int fd | const char __user * uargs | int flags | - | - | - | - |
313 | sched_setattr | sys_sched_setattr | 3 | pid_t pid | struct sched_attr __user * uattr | unsigned int flags | - | - | - | - |
314 | sched_getattr | sys_sched_getattr | 4 | pid_t pid | struct sched_attr __user * uattr | unsigned int usize | unsigned int flags | - | - | - |
315 | renameat2 | sys_renameat2 | 5 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | unsigned int flags | - | - |
316 | seccomp | sys_seccomp | 3 | unsigned int op | unsigned int flags | void __user * uargs | - | - | - | - |
317 | getrandom | sys_getrandom | 3 | char __user * buf | size_t count | unsigned int flags | - | - | - | - |
318 | memfd_create | sys_memfd_create | 2 | const char __user * uname | unsigned int flags | - | - | - | - | - |
319 | bpf | sys_bpf | 3 | int cmd | union bpf_attr __user * uattr | unsigned int size | - | - | - | - |
320 | execveat | compat_sys_execveat | 5 | int fd | const char __user * filename | const char __user *const __user * argv | const char __user *const __user * envp | int flags | - | - |
321 | userfaultfd | sys_userfaultfd | 1 | int flags | - | - | - | - | - | - |
322 | membarrier | sys_membarrier | 3 | int cmd | unsigned int flags | int cpu_id | - | - | - | - |
323 | mlock2 | sys_mlock2 | 3 | unsigned long start | size_t len | int flags | - | - | - | - |
324 | copy_file_range | sys_copy_file_range | 6 | int fd_in | loff_t __user * off_in | int fd_out | loff_t __user * off_out | size_t len | unsigned int flags | - |
325 | preadv2 | compat_sys_preadv2 | 6 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | rwf_t flags | - |
326 | pwritev2 | compat_sys_pwritev2 | 6 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | rwf_t flags | - |
327 | pkey_mprotect | sys_pkey_mprotect | 4 | unsigned long start | size_t len | unsigned long prot | int pkey | - | - | - |
328 | pkey_alloc | sys_pkey_alloc | 2 | unsigned long flags | unsigned long init_val | - | - | - | - | - |
329 | pkey_free | sys_pkey_free | 1 | int pkey | - | - | - | - | - | - |
330 | statx | sys_statx | 5 | int dfd | const char __user * filename | unsigned flags | unsigned int mask | struct statx __user * buffer | - | - |
331 | rseq | sys_rseq | 4 | struct rseq __user * rseq | u32 rseq_len | int flags | u32 sig | - | - | - |
332 | io_pgetevents | compat_sys_io_pgetevents | 6 | aio_context_t ctx_id | long min_nr | long nr | struct io_event __user * events | struct __kernel_timespec __user * timeout | const struct __aio_sigset __user * usig | - |
424 | pidfd_send_signal | sys_pidfd_send_signal | 4 | int pidfd | int sig | siginfo_t __user * info | unsigned int flags | - | - | - |
425 | io_uring_setup | sys_io_uring_setup | 2 | u32 entries | struct io_uring_params __user * params | - | - | - | - | - |
426 | io_uring_enter | sys_io_uring_enter | 6 | unsigned int fd | u32 to_submit | u32 min_complete | u32 flags | const void __user * argp | size_t argsz | - |
427 | io_uring_register | sys_io_uring_register | 4 | unsigned int fd | unsigned int opcode | void __user * arg | unsigned int nr_args | - | - | - |
428 | open_tree | sys_open_tree | 3 | int dfd | const char __user * filename | unsigned flags | - | - | - | - |
429 | move_mount | sys_move_mount | 5 | int from_dfd | const char __user * from_pathname | int to_dfd | const char __user * to_pathname | unsigned int flags | - | - |
430 | fsopen | sys_fsopen | 2 | const char __user * _fs_name | unsigned int flags | - | - | - | - | - |
431 | fsconfig | sys_fsconfig | 5 | int fd | unsigned int cmd | const char __user * _key | const void __user * _value | int aux | - | - |
432 | fsmount | sys_fsmount | 3 | int fs_fd | unsigned int flags | unsigned int attr_flags | - | - | - | - |
433 | fspick | sys_fspick | 3 | int dfd | const char __user * path | unsigned int flags | - | - | - | - |
434 | pidfd_open | sys_pidfd_open | 2 | pid_t pid | unsigned int flags | - | - | - | - | - |
435 | clone3 | __sys_clone3 | 2 | struct clone_args __user * uargs | size_t size | - | - | - | - | - |
436 | close_range | sys_close_range | 3 | unsigned int fd | unsigned int max_fd | unsigned int flags | - | - | - | - |
437 | openat2 | sys_openat2 | 4 | int dfd | const char __user * filename | struct open_how __user * how | size_t usize | - | - | - |
438 | pidfd_getfd | sys_pidfd_getfd | 3 | int pidfd | int fd | unsigned int flags | - | - | - | - |
439 | faccessat2 | sys_faccessat2 | 4 | int dfd | const char __user * filename | int mode | int flags | - | - | - |
440 | process_madvise | sys_process_madvise | 5 | int pidfd | const struct iovec __user * vec | size_t vlen | int behavior | unsigned int flags | - | - |
441 | epoll_pwait2 | compat_sys_epoll_pwait2 | 6 | int epfd | struct epoll_event __user * events | int maxevents | const struct __kernel_timespec __user * timeout | const sigset_t __user * sigmask | size_t sigsetsize | - |
442 | mount_setattr | sys_mount_setattr | 5 | int dfd | const char __user * path | unsigned int flags | struct mount_attr __user * uattr | size_t usize | - | - |
443 | quotactl_fd | sys_quotactl_fd | 4 | unsigned int fd | unsigned int cmd | qid_t id | void __user * addr | - | - | - |
445 | landlock_add_rule | sys_landlock_add_rule | 4 | const int ruleset_fd | const enum landlock_rule_type rule_type | const void __user *const rule_attr | const __u32 flags | - | - | - |
446 | landlock_restrict_self | sys_landlock_restrict_self | 2 | const int ruleset_fd | const __u32 flags | - | - | - | - | - |
448 | process_mrelease | sys_process_mrelease | 2 | int pidfd | unsigned int flags | - | - | - | - | - |
449 | futex_waitv | sys_futex_waitv | 5 | struct futex_waitv __user * waiters | unsigned int nr_futexes | unsigned int flags | struct __kernel_timespec __user * timeout | clockid_t clockid | - | - |
