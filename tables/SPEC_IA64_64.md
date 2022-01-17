
#  ia64 64-bit

| Syscall # | Name | Entry Points | # Arguments | arg0 | arg1 | arg2 | arg3 | arg4 | arg5 | arg6 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
1 | exit | sys_exit | 1 | int error_code | - | - | - | - | - | - |
2 | read | sys_read | 3 | unsigned int fd | char __user * buf | size_t count | - | - | - | - |
3 | write | sys_write | 3 | unsigned int fd | const char __user * buf | size_t count | - | - | - | - |
4 | open | sys_open | 3 | const char __user * filename | int flags | umode_t mode | - | - | - | - |
5 | close | sys_close | 1 | unsigned int fd | - | - | - | - | - | - |
6 | creat | sys_creat | 2 | const char __user * pathname | umode_t mode | - | - | - | - | - |
7 | link | sys_link | 2 | const char __user * oldname | const char __user * newname | - | - | - | - | - |
8 | unlink | sys_unlink | 1 | const char __user * pathname | - | - | - | - | - | - |
9 | execve | ia64_execve | 3 | const char __user * filename | const char __user *const __user * argv | const char __user *const __user * envp | - | - | - | - |
10 | chdir | sys_chdir | 1 | const char __user * filename | - | - | - | - | - | - |
11 | fchdir | sys_fchdir | 1 | unsigned int fd | - | - | - | - | - | - |
12 | utimes | sys_utimes | 2 | char __user * filename | struct __kernel_old_timeval __user * utimes | - | - | - | - | - |
13 | mknod | sys_mknod | 3 | const char __user * filename | umode_t mode | unsigned dev | - | - | - | - |
14 | chmod | sys_chmod | 2 | const char __user * filename | umode_t mode | - | - | - | - | - |
15 | chown | sys_chown | 3 | const char __user * filename | uid_t user | gid_t group | - | - | - | - |
16 | lseek | sys_lseek | 3 | unsigned int fd | off_t offset | unsigned int whence | - | - | - | - |
17 | getpid | sys_getpid | 0 | - | - | - | - | - | - | - |
18 | getppid | sys_getppid | 0 | - | - | - | - | - | - | - |
19 | mount | sys_mount | 5 | char __user * dev_name | char __user * dir_name | char __user * type | unsigned long flags | void __user * data | - | - |
20 | umount | sys_umount | 2 | char __user * name | int flags | - | - | - | - | - |
21 | setuid | sys_setuid | 1 | uid_t uid | - | - | - | - | - | - |
22 | getuid | sys_getuid | 0 | - | - | - | - | - | - | - |
23 | geteuid | sys_geteuid | 0 | - | - | - | - | - | - | - |
24 | ptrace | sys_ptrace | 4 | long request | long pid | unsigned long addr | unsigned long data | - | - | - |
25 | access | sys_access | 2 | const char __user * filename | int mode | - | - | - | - | - |
26 | sync | sys_sync | 0 | - | - | - | - | - | - | - |
27 | fsync | sys_fsync | 1 | unsigned int fd | - | - | - | - | - | - |
28 | fdatasync | sys_fdatasync | 1 | unsigned int fd | - | - | - | - | - | - |
29 | kill | sys_kill | 2 | pid_t pid | int sig | - | - | - | - | - |
30 | rename | sys_rename | 2 | const char __user * oldname | const char __user * newname | - | - | - | - | - |
31 | mkdir | sys_mkdir | 2 | const char __user * pathname | umode_t mode | - | - | - | - | - |
32 | rmdir | sys_rmdir | 1 | const char __user * pathname | - | - | - | - | - | - |
33 | dup | sys_dup | 1 | unsigned int fildes | - | - | - | - | - | - |
34 | pipe | sys_ia64_pipe | 1 | int __user * fildes | - | - | - | - | - | - |
35 | times | sys_times | 1 | struct tms __user * tbuf | - | - | - | - | - | - |
36 | brk | ia64_brk | 1 | unsigned long brk | - | - | - | - | - | - |
36 | brk | ia64_brk | 1 | unsigned long brk | - | - | - | - | - | - |
37 | setgid | sys_setgid | 1 | gid_t gid | - | - | - | - | - | - |
38 | getgid | sys_getgid | 0 | - | - | - | - | - | - | - |
39 | getegid | sys_getegid | 0 | - | - | - | - | - | - | - |
40 | acct | sys_acct | 1 | const char __user * name | - | - | - | - | - | - |
41 | ioctl | sys_ioctl | 3 | unsigned int fd | unsigned int cmd | unsigned long arg | - | - | - | - |
42 | fcntl | sys_fcntl | 3 | unsigned int fd | unsigned int cmd | unsigned long arg | - | - | - | - |
44 | chroot | sys_chroot | 1 | const char __user * filename | - | - | - | - | - | - |
45 | ustat | sys_ustat | 2 | unsigned dev | struct ustat __user * ubuf | - | - | - | - | - |
46 | dup2 | sys_dup2 | 2 | unsigned int oldfd | unsigned int newfd | - | - | - | - | - |
47 | setreuid | sys_setreuid | 2 | uid_t ruid | uid_t euid | - | - | - | - | - |
48 | setregid | sys_setregid | 2 | gid_t rgid | gid_t egid | - | - | - | - | - |
49 | getresuid | sys_getresuid | 3 | uid_t __user * ruidp | uid_t __user * euidp | uid_t __user * suidp | - | - | - | - |
50 | setresuid | sys_setresuid | 3 | uid_t ruid | uid_t euid | uid_t suid | - | - | - | - |
51 | getresgid | sys_getresgid | 3 | gid_t __user * rgidp | gid_t __user * egidp | gid_t __user * sgidp | - | - | - | - |
52 | setresgid | sys_setresgid | 3 | gid_t rgid | gid_t egid | gid_t sgid | - | - | - | - |
53 | getgroups | sys_getgroups | 2 | int gidsetsize | gid_t __user * grouplist | - | - | - | - | - |
54 | setgroups | sys_setgroups | 2 | int gidsetsize | gid_t __user * grouplist | - | - | - | - | - |
55 | getpgid | sys_getpgid | 1 | pid_t pid | - | - | - | - | - | - |
56 | setpgid | sys_setpgid | 2 | pid_t pid | pid_t pgid | - | - | - | - | - |
57 | setsid | sys_setsid | 0 | - | - | - | - | - | - | - |
58 | getsid | sys_getsid | 1 | pid_t pid | - | - | - | - | - | - |
59 | sethostname | sys_sethostname | 2 | char __user * name | int len | - | - | - | - | - |
60 | setrlimit | sys_setrlimit | 2 | unsigned int resource | struct rlimit __user * rlim | - | - | - | - | - |
61 | getrlimit | sys_getrlimit | 2 | unsigned int resource | struct rlimit __user * rlim | - | - | - | - | - |
62 | getrusage | sys_getrusage | 2 | int who | struct rusage __user * ru | - | - | - | - | - |
63 | gettimeofday | sys_gettimeofday | 2 | struct __kernel_old_timeval __user * tv | struct timezone __user * tz | - | - | - | - | - |
64 | settimeofday | sys_settimeofday | 2 | struct __kernel_old_timeval __user * tv | struct timezone __user * tz | - | - | - | - | - |
65 | select | sys_select | 5 | int n | fd_set __user * inp | fd_set __user * outp | fd_set __user * exp | struct __kernel_old_timeval __user * tvp | - | - |
66 | poll | sys_poll | 3 | struct pollfd __user * ufds | unsigned int nfds | int timeout_msecs | - | - | - | - |
67 | symlink | sys_symlink | 2 | const char __user * oldname | const char __user * newname | - | - | - | - | - |
68 | readlink | sys_readlink | 3 | const char __user * path | char __user * buf | int bufsiz | - | - | - | - |
69 | uselib | sys_uselib | 1 | const char __user * library | - | - | - | - | - | - |
70 | swapon | sys_swapon | 2 | const char __user * specialfile | int swap_flags | - | - | - | - | - |
71 | swapoff | sys_swapoff | 1 | const char __user * specialfile | - | - | - | - | - | - |
72 | reboot | sys_reboot | 4 | int magic1 | int magic2 | unsigned int cmd | void __user * arg | - | - | - |
73 | truncate | sys_truncate | 2 | const char __user * path | long length | - | - | - | - | - |
74 | ftruncate | sys_ftruncate | 2 | unsigned int fd | unsigned long length | - | - | - | - | - |
75 | fchmod | sys_fchmod | 2 | unsigned int fd | umode_t mode | - | - | - | - | - |
76 | fchown | sys_fchown | 3 | unsigned int fd | uid_t user | gid_t group | - | - | - | - |
77 | getpriority | ia64_getpriority | 2 | int which | int who | - | - | - | - | - |
78 | setpriority | sys_setpriority | 3 | int which | int who | int niceval | - | - | - | - |
79 | statfs | sys_statfs | 2 | const char __user * pathname | struct statfs __user * buf | - | - | - | - | - |
80 | fstatfs | sys_fstatfs | 2 | unsigned int fd | struct statfs __user * buf | - | - | - | - | - |
81 | gettid | sys_gettid | 0 | - | - | - | - | - | - | - |
82 | semget | sys_semget | 3 | key_t key | int nsems | int semflg | - | - | - | - |
83 | semop | sys_semop | 3 | int semid | struct sembuf __user * tsops | unsigned nsops | - | - | - | - |
84 | semctl | sys_semctl | 4 | int semid | int semnum | int cmd | unsigned long arg | - | - | - |
85 | msgget | sys_msgget | 2 | key_t key | int msgflg | - | - | - | - | - |
86 | msgsnd | sys_msgsnd | 4 | int msqid | struct msgbuf __user * msgp | size_t msgsz | int msgflg | - | - | - |
87 | msgrcv | sys_msgrcv | 5 | int msqid | struct msgbuf __user * msgp | size_t msgsz | long msgtyp | int msgflg | - | - |
88 | msgctl | sys_msgctl | 3 | int msqid | int cmd | struct msqid_ds __user * buf | - | - | - | - |
89 | shmget | sys_shmget | 3 | key_t key | size_t size | int shmflg | - | - | - | - |
90 | shmat | sys_shmat | 3 | int shmid | char __user * shmaddr | int shmflg | - | - | - | - |
91 | shmdt | sys_shmdt | 1 | char __user * shmaddr | - | - | - | - | - | - |
92 | shmctl | sys_shmctl | 3 | int shmid | int cmd | struct shmid_ds __user * buf | - | - | - | - |
93 | syslog | sys_syslog | 3 | int type | char __user * buf | int len | - | - | - | - |
94 | setitimer | sys_setitimer | 3 | int which | struct __kernel_old_itimerval __user * value | struct __kernel_old_itimerval __user * ovalue | - | - | - | - |
95 | getitimer | sys_getitimer | 2 | int which | struct __kernel_old_itimerval __user * value | - | - | - | - | - |
99 | vhangup | sys_vhangup | 0 | - | - | - | - | - | - | - |
100 | lchown | sys_lchown | 3 | const char __user * filename | uid_t user | gid_t group | - | - | - | - |
101 | remap_file_pages | sys_remap_file_pages | 5 | unsigned long start | unsigned long size | unsigned long prot | unsigned long pgoff | unsigned long flags | - | - |
104 | clone | sys_clone | 5 | unsigned long clone_flags | unsigned long newsp | int __user * parent_tidptr | unsigned long tls | int __user * child_tidptr | - | - |
104 | clone | sys_clone | 5 | unsigned long newsp | unsigned long clone_flags | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - | - |
104 | clone | sys_clone | 6 | unsigned long clone_flags | unsigned long newsp | int stack_size | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - |
104 | clone | sys_clone | 5 | unsigned long clone_flags | unsigned long newsp | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - | - |
105 | setdomainname | sys_setdomainname | 2 | char __user * name | int len | - | - | - | - | - |
106 | newuname | sys_newuname | 1 | struct new_utsname __user * name | - | - | - | - | - | - |
106 | uname | sys_newuname | 1 | struct old_utsname __user * name | - | - | - | - | - | - |
107 | adjtimex | sys_adjtimex | 1 | struct __kernel_timex __user * txc_p | - | - | - | - | - | - |
109 | init_module | sys_init_module | 3 | void __user * umod | unsigned long len | const char __user * uargs | - | - | - | - |
110 | delete_module | sys_delete_module | 2 | const char __user * name_user | unsigned int flags | - | - | - | - | - |
113 | quotactl | sys_quotactl | 4 | unsigned int cmd | const char __user * special | qid_t id | void __user * addr | - | - | - |
115 | sysfs | sys_sysfs | 3 | int option | unsigned long arg1 | unsigned long arg2 | - | - | - | - |
116 | personality | sys_personality | 1 | unsigned int personality | - | - | - | - | - | - |
118 | setfsuid | sys_setfsuid | 1 | uid_t uid | - | - | - | - | - | - |
119 | setfsgid | sys_setfsgid | 1 | gid_t gid | - | - | - | - | - | - |
120 | getdents | sys_getdents | 3 | unsigned int fd | struct linux_dirent __user * dirent | unsigned int count | - | - | - | - |
121 | flock | sys_flock | 2 | unsigned int fd | unsigned int cmd | - | - | - | - | - |
122 | readv | sys_readv | 3 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | - | - | - | - |
123 | writev | sys_writev | 3 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | - | - | - | - |
124 | pread64 | sys_pread64 | 4 | unsigned int fd | char __user * buf | size_t count | loff_t pos | - | - | - |
125 | pwrite64 | sys_pwrite64 | 4 | unsigned int fd | const char __user * buf | size_t count | loff_t pos | - | - | - |
128 | munmap | sys_munmap | 2 | unsigned long addr | size_t len | - | - | - | - | - |
128 | munmap | sys_munmap | 2 | unsigned long addr | size_t len | - | - | - | - | - |
129 | mlock | sys_mlock | 2 | unsigned long start | size_t len | - | - | - | - | - |
130 | mlockall | sys_mlockall | 1 | int flags | - | - | - | - | - | - |
131 | mprotect | sys_mprotect | 3 | unsigned long start | size_t len | unsigned long prot | - | - | - | - |
132 | mremap | ia64_mremap | 5 | unsigned long addr | unsigned long old_len | unsigned long new_len | unsigned long flags | unsigned long new_addr | - | - |
132 | mremap | ia64_mremap | 5 | unsigned long addr | unsigned long old_len | unsigned long new_len | unsigned long flags | unsigned long new_addr | - | - |
133 | msync | sys_msync | 3 | unsigned long start | size_t len | int flags | - | - | - | - |
134 | munlock | sys_munlock | 2 | unsigned long start | size_t len | - | - | - | - | - |
135 | munlockall | sys_munlockall | 0 | - | - | - | - | - | - | - |
136 | sched_getparam | sys_sched_getparam | 2 | pid_t pid | struct sched_param __user * param | - | - | - | - | - |
137 | sched_setparam | sys_sched_setparam | 2 | pid_t pid | struct sched_param __user * param | - | - | - | - | - |
138 | sched_getscheduler | sys_sched_getscheduler | 1 | pid_t pid | - | - | - | - | - | - |
139 | sched_setscheduler | sys_sched_setscheduler | 3 | pid_t pid | int policy | struct sched_param __user * param | - | - | - | - |
140 | sched_yield | sys_sched_yield | 0 | - | - | - | - | - | - | - |
141 | sched_get_priority_max | sys_sched_get_priority_max | 1 | int policy | - | - | - | - | - | - |
142 | sched_get_priority_min | sys_sched_get_priority_min | 1 | int policy | - | - | - | - | - | - |
143 | sched_rr_get_interval | sys_sched_rr_get_interval | 2 | pid_t pid | struct __kernel_timespec __user * interval | - | - | - | - | - |
144 | nanosleep | sys_nanosleep | 2 | struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - | - | - |
149 | pciconfig_read | sys_pciconfig_read | 5 | unsigned long bus | unsigned long dfn | unsigned long off | unsigned long len | void __user * buf | - | - |
150 | pciconfig_write | sys_pciconfig_write | 5 | unsigned long bus | unsigned long dfn | unsigned long off | unsigned long len | void __user * buf | - | - |
152 | sigaltstack | sys_sigaltstack | 2 | const stack_t __user * uss | stack_t __user * uoss | - | - | - | - | - |
154 | rt_sigpending | sys_rt_sigpending | 2 | sigset_t __user * uset | size_t sigsetsize | - | - | - | - | - |
155 | rt_sigprocmask | sys_rt_sigprocmask | 4 | int how | sigset_t __user * nset | sigset_t __user * oset | size_t sigsetsize | - | - | - |
156 | rt_sigqueueinfo | sys_rt_sigqueueinfo | 3 | pid_t pid | int sig | siginfo_t __user * uinfo | - | - | - | - |
158 | rt_sigsuspend | sys_rt_sigsuspend | 2 | sigset_t __user * unewset | size_t sigsetsize | - | - | - | - | - |
159 | rt_sigtimedwait | sys_rt_sigtimedwait | 4 | const sigset_t __user * uthese | siginfo_t __user * uinfo | const struct __kernel_timespec __user * uts | size_t sigsetsize | - | - | - |
160 | getcwd | sys_getcwd | 2 | char __user * buf | unsigned long size | - | - | - | - | - |
161 | capget | sys_capget | 2 | cap_user_header_t header | cap_user_data_t dataptr | - | - | - | - | - |
162 | capset | sys_capset | 2 | cap_user_header_t header | const cap_user_data_t data | - | - | - | - | - |
163 | sendfile | sys_sendfile64 | 4 | int out_fd | int in_fd | off_t __user * offset | size_t count | - | - | - |
163 | sendfile64 | sys_sendfile64 | 4 | int out_fd | int in_fd | loff_t __user * offset | size_t count | - | - | - |
166 | socket | sys_socket | 3 | int family | int type | int protocol | - | - | - | - |
167 | bind | sys_bind | 3 | int fd | struct sockaddr __user * umyaddr | int addrlen | - | - | - | - |
168 | connect | sys_connect | 3 | int fd | struct sockaddr __user * uservaddr | int addrlen | - | - | - | - |
169 | listen | sys_listen | 2 | int fd | int backlog | - | - | - | - | - |
170 | accept | sys_accept | 3 | int fd | struct sockaddr __user * upeer_sockaddr | int __user * upeer_addrlen | - | - | - | - |
171 | getsockname | sys_getsockname | 3 | int fd | struct sockaddr __user * usockaddr | int __user * usockaddr_len | - | - | - | - |
172 | getpeername | sys_getpeername | 3 | int fd | struct sockaddr __user * usockaddr | int __user * usockaddr_len | - | - | - | - |
173 | socketpair | sys_socketpair | 4 | int family | int type | int protocol | int __user * usockvec | - | - | - |
174 | send | sys_send | 4 | int fd | void __user * buff | size_t len | unsigned int flags | - | - | - |
175 | sendto | sys_sendto | 6 | int fd | void __user * buff | size_t len | unsigned int flags | struct sockaddr __user * addr | int addr_len | - |
176 | recv | sys_recv | 4 | int fd | void __user * ubuf | size_t size | unsigned int flags | - | - | - |
177 | recvfrom | sys_recvfrom | 6 | int fd | void __user * ubuf | size_t size | unsigned int flags | struct sockaddr __user * addr | int __user * addr_len | - |
178 | shutdown | sys_shutdown | 2 | int fd | int how | - | - | - | - | - |
179 | setsockopt | sys_setsockopt | 5 | int fd | int level | int optname | char __user * optval | int optlen | - | - |
180 | getsockopt | sys_getsockopt | 5 | int fd | int level | int optname | char __user * optval | int __user * optlen | - | - |
181 | sendmsg | sys_sendmsg | 3 | int fd | struct user_msghdr __user * msg | unsigned int flags | - | - | - | - |
182 | recvmsg | sys_recvmsg | 3 | int fd | struct user_msghdr __user * msg | unsigned int flags | - | - | - | - |
183 | pivot_root | sys_pivot_root | 2 | const char __user * new_root | const char __user * put_old | - | - | - | - | - |
184 | mincore | sys_mincore | 3 | unsigned long start | size_t len | unsigned char __user * vec | - | - | - | - |
185 | madvise | sys_madvise | 3 | unsigned long start | size_t len_in | int behavior | - | - | - | - |
186 | stat | sys_newstat | 2 | const char __user * filename | struct __old_kernel_stat __user * statbuf | - | - | - | - | - |
186 | newstat | sys_newstat | 2 | const char __user * filename | struct stat __user * statbuf | - | - | - | - | - |
187 | lstat | sys_newlstat | 2 | const char __user * filename | struct __old_kernel_stat __user * statbuf | - | - | - | - | - |
187 | newlstat | sys_newlstat | 2 | const char __user * filename | struct stat __user * statbuf | - | - | - | - | - |
188 | fstat | sys_newfstat | 2 | unsigned int fd | struct __old_kernel_stat __user * statbuf | - | - | - | - | - |
188 | newfstat | sys_newfstat | 2 | unsigned int fd | struct stat __user * statbuf | - | - | - | - | - |
190 | getdents64 | sys_getdents64 | 3 | unsigned int fd | struct linux_dirent64 __user * dirent | unsigned int count | - | - | - | - |
192 | readahead | sys_readahead | 3 | int fd | loff_t offset | size_t count | - | - | - | - |
193 | setxattr | sys_setxattr | 5 | const char __user * pathname | const char __user * name | const void __user * value | size_t size | int flags | - | - |
194 | lsetxattr | sys_lsetxattr | 5 | const char __user * pathname | const char __user * name | const void __user * value | size_t size | int flags | - | - |
195 | fsetxattr | sys_fsetxattr | 5 | int fd | const char __user * name | const void __user * value | size_t size | int flags | - | - |
196 | getxattr | sys_getxattr | 4 | const char __user * pathname | const char __user * name | void __user * value | size_t size | - | - | - |
197 | lgetxattr | sys_lgetxattr | 4 | const char __user * pathname | const char __user * name | void __user * value | size_t size | - | - | - |
198 | fgetxattr | sys_fgetxattr | 4 | int fd | const char __user * name | void __user * value | size_t size | - | - | - |
199 | listxattr | sys_listxattr | 3 | const char __user * pathname | char __user * list | size_t size | - | - | - | - |
200 | llistxattr | sys_llistxattr | 3 | const char __user * pathname | char __user * list | size_t size | - | - | - | - |
201 | flistxattr | sys_flistxattr | 3 | int fd | char __user * list | size_t size | - | - | - | - |
202 | removexattr | sys_removexattr | 2 | const char __user * pathname | const char __user * name | - | - | - | - | - |
203 | lremovexattr | sys_lremovexattr | 2 | const char __user * pathname | const char __user * name | - | - | - | - | - |
204 | fremovexattr | sys_fremovexattr | 2 | int fd | const char __user * name | - | - | - | - | - |
205 | tkill | sys_tkill | 2 | pid_t pid | int sig | - | - | - | - | - |
206 | futex | sys_futex | 6 | u32 __user * uaddr | int op | u32 val | const struct __kernel_timespec __user * utime | u32 __user * uaddr2 | u32 val3 | - |
207 | sched_setaffinity | sys_sched_setaffinity | 3 | pid_t pid | unsigned int len | unsigned long __user * user_mask_ptr | - | - | - | - |
208 | sched_getaffinity | sys_sched_getaffinity | 3 | pid_t pid | unsigned int len | unsigned long __user * user_mask_ptr | - | - | - | - |
209 | set_tid_address | sys_set_tid_address | 1 | int __user * tidptr | - | - | - | - | - | - |
210 | fadvise64_64 | sys_fadvise64_64 | 4 | int fd | loff_t offset | loff_t len | int advice | - | - | - |
210 | fadvise64 | sys_fadvise64_64 | 4 | int fd | loff_t offset | size_t len | int advice | - | - | - |
211 | tgkill | sys_tgkill | 3 | pid_t tgid | pid_t pid | int sig | - | - | - | - |
212 | exit_group | sys_exit_group | 1 | int error_code | - | - | - | - | - | - |
214 | io_setup | sys_io_setup | 2 | unsigned nr_events | aio_context_t __user * ctxp | - | - | - | - | - |
215 | io_destroy | sys_io_destroy | 1 | aio_context_t ctx | - | - | - | - | - | - |
216 | io_getevents | sys_io_getevents | 5 | aio_context_t ctx_id | long min_nr | long nr | struct io_event __user * events | struct __kernel_timespec __user * timeout | - | - |
217 | io_submit | sys_io_submit | 3 | aio_context_t ctx_id | long nr | struct iocb __user * __user * iocbpp | - | - | - | - |
218 | io_cancel | sys_io_cancel | 3 | aio_context_t ctx_id | struct iocb __user * iocb | struct io_event __user * result | - | - | - | - |
219 | epoll_create | sys_epoll_create | 1 | int size | - | - | - | - | - | - |
220 | epoll_ctl | sys_epoll_ctl | 4 | int epfd | int op | int fd | struct epoll_event __user * event | - | - | - |
221 | epoll_wait | sys_epoll_wait | 4 | int epfd | struct epoll_event __user * events | int maxevents | int timeout | - | - | - |
222 | restart_syscall | sys_restart_syscall | 0 | - | - | - | - | - | - | - |
223 | semtimedop | sys_semtimedop | 4 | int semid | struct sembuf __user * tsops | unsigned int nsops | const struct __kernel_timespec __user * timeout | - | - | - |
224 | timer_create | sys_timer_create | 3 | const clockid_t which_clock | struct sigevent __user * timer_event_spec | timer_t __user * created_timer_id | - | - | - | - |
225 | timer_settime | sys_timer_settime | 4 | timer_t timer_id | int flags | const struct __kernel_itimerspec __user * new_setting | struct __kernel_itimerspec __user * old_setting | - | - | - |
226 | timer_gettime | sys_timer_gettime | 2 | timer_t timer_id | struct __kernel_itimerspec __user * setting | - | - | - | - | - |
227 | timer_getoverrun | sys_timer_getoverrun | 1 | timer_t timer_id | - | - | - | - | - | - |
228 | timer_delete | sys_timer_delete | 1 | timer_t timer_id | - | - | - | - | - | - |
229 | clock_settime | sys_clock_settime | 2 | const clockid_t which_clock | const struct __kernel_timespec __user * tp | - | - | - | - | - |
229 | clock_settime | sys_clock_settime | 2 | const clockid_t which_clock | const struct __kernel_timespec __user * tp | - | - | - | - | - |
230 | clock_gettime | sys_clock_gettime | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
230 | clock_gettime | sys_clock_gettime | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
231 | clock_getres | sys_clock_getres | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
231 | clock_getres | sys_clock_getres | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
232 | clock_nanosleep | sys_clock_nanosleep | 4 | const clockid_t which_clock | int flags | const struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - |
232 | clock_nanosleep | sys_clock_nanosleep | 4 | const clockid_t which_clock | int flags | const struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - |
233 | fstatfs64 | sys_fstatfs64 | 3 | unsigned int fd | size_t sz | struct statfs64 __user * buf | - | - | - | - |
234 | statfs64 | sys_statfs64 | 3 | const char __user * pathname | size_t sz | struct statfs64 __user * buf | - | - | - | - |
235 | mbind | sys_mbind | 6 | unsigned long start | unsigned long len | unsigned long mode | const unsigned long __user * nmask | unsigned long maxnode | unsigned int flags | - |
236 | get_mempolicy | sys_get_mempolicy | 5 | int __user * policy | unsigned long __user * nmask | unsigned long maxnode | unsigned long addr | unsigned long flags | - | - |
237 | set_mempolicy | sys_set_mempolicy | 3 | int mode | const unsigned long __user * nmask | unsigned long maxnode | - | - | - | - |
238 | mq_open | sys_mq_open | 4 | const char __user * u_name | int oflag | umode_t mode | struct mq_attr __user * u_attr | - | - | - |
239 | mq_unlink | sys_mq_unlink | 1 | const char __user * u_name | - | - | - | - | - | - |
240 | mq_timedsend | sys_mq_timedsend | 5 | mqd_t mqdes | const char __user * u_msg_ptr | size_t msg_len | unsigned int msg_prio | const struct __kernel_timespec __user * u_abs_timeout | - | - |
241 | mq_timedreceive | sys_mq_timedreceive | 5 | mqd_t mqdes | char __user * u_msg_ptr | size_t msg_len | unsigned int __user * u_msg_prio | const struct __kernel_timespec __user * u_abs_timeout | - | - |
244 | kexec_load | sys_kexec_load | 4 | unsigned long entry | unsigned long nr_segments | struct kexec_segment __user * segments | unsigned long flags | - | - | - |
247 | add_key | sys_add_key | 5 | const char __user * _type | const char __user * _description | const void __user * _payload | size_t plen | key_serial_t ringid | - | - |
248 | request_key | sys_request_key | 4 | const char __user * _type | const char __user * _description | const char __user * _callout_info | key_serial_t destringid | - | - | - |
249 | keyctl | sys_keyctl | 5 | int option | unsigned long arg2 | unsigned long arg3 | unsigned long arg4 | unsigned long arg5 | - | - |
250 | ioprio_set | sys_ioprio_set | 3 | int which | int who | int ioprio | - | - | - | - |
251 | ioprio_get | sys_ioprio_get | 2 | int which | int who | - | - | - | - | - |
252 | move_pages | sys_move_pages | 6 | pid_t pid | unsigned long nr_pages | const void __user * __user * pages | const int __user * nodes | int __user * status | int flags | - |
253 | inotify_init | sys_inotify_init | 0 | - | - | - | - | - | - | - |
254 | inotify_add_watch | sys_inotify_add_watch | 3 | int fd | const char __user * pathname | u32 mask | - | - | - | - |
255 | inotify_rm_watch | sys_inotify_rm_watch | 2 | int fd | __s32 wd | - | - | - | - | - |
256 | migrate_pages | sys_migrate_pages | 4 | pid_t pid | unsigned long maxnode | const unsigned long __user * old_nodes | const unsigned long __user * new_nodes | - | - | - |
257 | openat | sys_openat | 4 | int dfd | const char __user * filename | int flags | umode_t mode | - | - | - |
258 | mkdirat | sys_mkdirat | 3 | int dfd | const char __user * pathname | umode_t mode | - | - | - | - |
259 | mknodat | sys_mknodat | 4 | int dfd | const char __user * filename | umode_t mode | unsigned int dev | - | - | - |
260 | fchownat | sys_fchownat | 5 | int dfd | const char __user * filename | uid_t user | gid_t group | int flag | - | - |
261 | futimesat | sys_futimesat | 3 | int dfd | const char __user * filename | struct __kernel_old_timeval __user * utimes | - | - | - | - |
262 | newfstatat | sys_newfstatat | 4 | int dfd | const char __user * filename | struct stat __user * statbuf | int flag | - | - | - |
263 | unlinkat | sys_unlinkat | 3 | int dfd | const char __user * pathname | int flag | - | - | - | - |
264 | renameat | sys_renameat | 4 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | - | - | - |
265 | linkat | sys_linkat | 5 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | int flags | - | - |
266 | symlinkat | sys_symlinkat | 3 | const char __user * oldname | int newdfd | const char __user * newname | - | - | - | - |
267 | readlinkat | sys_readlinkat | 4 | int dfd | const char __user * pathname | char __user * buf | int bufsiz | - | - | - |
268 | fchmodat | sys_fchmodat | 3 | int dfd | const char __user * filename | umode_t mode | - | - | - | - |
269 | faccessat | sys_faccessat | 3 | int dfd | const char __user * filename | int mode | - | - | - | - |
270 | pselect6 | sys_pselect6 | 6 | int n | fd_set __user * inp | fd_set __user * outp | fd_set __user * exp | struct __kernel_timespec __user * tsp | void __user * sig | - |
271 | ppoll | sys_ppoll | 5 | struct pollfd __user * ufds | unsigned int nfds | struct __kernel_timespec __user * tsp | const sigset_t __user * sigmask | size_t sigsetsize | - | - |
272 | unshare | sys_unshare | 1 | unsigned long unshare_flags | - | - | - | - | - | - |
273 | splice | sys_splice | 6 | int fd_in | loff_t __user * off_in | int fd_out | loff_t __user * off_out | size_t len | unsigned int flags | - |
274 | set_robust_list | sys_set_robust_list | 2 | struct robust_list_head __user * head | size_t len | - | - | - | - | - |
275 | get_robust_list | sys_get_robust_list | 3 | int pid | struct robust_list_head __user * __user * head_ptr | size_t __user * len_ptr | - | - | - | - |
276 | sync_file_range | sys_sync_file_range | 4 | int fd | loff_t offset | loff_t nbytes | unsigned int flags | - | - | - |
277 | tee | sys_tee | 4 | int fdin | int fdout | size_t len | unsigned int flags | - | - | - |
278 | vmsplice | sys_vmsplice | 4 | int fd | const struct iovec __user * uiov | unsigned long nr_segs | unsigned int flags | - | - | - |
279 | fallocate | sys_fallocate | 4 | int fd | int mode | loff_t offset | loff_t len | - | - | - |
281 | epoll_pwait | sys_epoll_pwait | 6 | int epfd | struct epoll_event __user * events | int maxevents | int timeout | const sigset_t __user * sigmask | size_t sigsetsize | - |
282 | utimensat | sys_utimensat | 4 | int dfd | const char __user * filename | struct __kernel_timespec __user * utimes | int flags | - | - | - |
283 | signalfd | sys_signalfd | 3 | int ufd | sigset_t __user * user_mask | size_t sizemask | - | - | - | - |
285 | eventfd | sys_eventfd | 1 | unsigned int count | - | - | - | - | - | - |
286 | timerfd_create | sys_timerfd_create | 2 | int clockid | int flags | - | - | - | - | - |
287 | timerfd_settime | sys_timerfd_settime | 4 | int ufd | int flags | const struct __kernel_itimerspec __user * utmr | struct __kernel_itimerspec __user * otmr | - | - | - |
288 | timerfd_gettime | sys_timerfd_gettime | 2 | int ufd | struct __kernel_itimerspec __user * otmr | - | - | - | - | - |
289 | signalfd4 | sys_signalfd4 | 4 | int ufd | sigset_t __user * user_mask | size_t sizemask | int flags | - | - | - |
290 | eventfd2 | sys_eventfd2 | 2 | unsigned int count | int flags | - | - | - | - | - |
291 | epoll_create1 | sys_epoll_create1 | 1 | int flags | - | - | - | - | - | - |
292 | dup3 | sys_dup3 | 3 | unsigned int oldfd | unsigned int newfd | int flags | - | - | - | - |
293 | pipe2 | sys_pipe2 | 2 | int __user * fildes | int flags | - | - | - | - | - |
294 | inotify_init1 | sys_inotify_init1 | 1 | int flags | - | - | - | - | - | - |
295 | preadv | sys_preadv | 5 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | - | - |
296 | pwritev | sys_pwritev | 5 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | - | - |
297 | rt_tgsigqueueinfo | sys_rt_tgsigqueueinfo | 4 | pid_t tgid | pid_t pid | int sig | siginfo_t __user * uinfo | - | - | - |
298 | recvmmsg | sys_recvmmsg | 5 | int fd | struct mmsghdr __user * mmsg | unsigned int vlen | unsigned int flags | struct __kernel_timespec __user * timeout | - | - |
299 | fanotify_init | sys_fanotify_init | 2 | unsigned int flags | unsigned int event_f_flags | - | - | - | - | - |
300 | fanotify_mark | sys_fanotify_mark | 5 | int fanotify_fd | unsigned int flags | __u64 mask | int dfd | const char __user * pathname | - | - |
301 | prlimit64 | sys_prlimit64 | 4 | pid_t pid | unsigned int resource | const struct rlimit64 __user * new_rlim | struct rlimit64 __user * old_rlim | - | - | - |
302 | name_to_handle_at | sys_name_to_handle_at | 5 | int dfd | const char __user * name | struct file_handle __user * handle | int __user * mnt_id | int flag | - | - |
303 | open_by_handle_at | sys_open_by_handle_at | 3 | int mountdirfd | struct file_handle __user * handle | int flags | - | - | - | - |
304 | clock_adjtime | sys_clock_adjtime | 2 | const clockid_t which_clock | struct __kernel_timex __user * utx | - | - | - | - | - |
305 | syncfs | sys_syncfs | 1 | int fd | - | - | - | - | - | - |
306 | setns | sys_setns | 2 | int fd | int flags | - | - | - | - | - |
307 | sendmmsg | sys_sendmmsg | 4 | int fd | struct mmsghdr __user * mmsg | unsigned int vlen | unsigned int flags | - | - | - |
308 | process_vm_readv | sys_process_vm_readv | 6 | pid_t pid | const struct iovec __user * lvec | unsigned long liovcnt | const struct iovec __user * rvec | unsigned long riovcnt | unsigned long flags | - |
309 | process_vm_writev | sys_process_vm_writev | 6 | pid_t pid | const struct iovec __user * lvec | unsigned long liovcnt | const struct iovec __user * rvec | unsigned long riovcnt | unsigned long flags | - |
310 | accept4 | sys_accept4 | 4 | int fd | struct sockaddr __user * upeer_sockaddr | int __user * upeer_addrlen | int flags | - | - | - |
311 | finit_module | sys_finit_module | 3 | int fd | const char __user * uargs | int flags | - | - | - | - |
312 | sched_setattr | sys_sched_setattr | 3 | pid_t pid | struct sched_attr __user * uattr | unsigned int flags | - | - | - | - |
313 | sched_getattr | sys_sched_getattr | 4 | pid_t pid | struct sched_attr __user * uattr | unsigned int usize | unsigned int flags | - | - | - |
314 | renameat2 | sys_renameat2 | 5 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | unsigned int flags | - | - |
315 | getrandom | sys_getrandom | 3 | char __user * buf | size_t count | unsigned int flags | - | - | - | - |
316 | memfd_create | sys_memfd_create | 2 | const char __user * uname | unsigned int flags | - | - | - | - | - |
317 | bpf | sys_bpf | 3 | int cmd | union bpf_attr __user * uattr | unsigned int size | - | - | - | - |
318 | execveat | sys_execveat | 5 | int fd | const char __user * filename | const char __user *const __user * argv | const char __user *const __user * envp | int flags | - | - |
319 | userfaultfd | sys_userfaultfd | 1 | int flags | - | - | - | - | - | - |
320 | membarrier | sys_membarrier | 3 | int cmd | unsigned int flags | int cpu_id | - | - | - | - |
321 | kcmp | sys_kcmp | 5 | pid_t pid1 | pid_t pid2 | int type | unsigned long idx1 | unsigned long idx2 | - | - |
322 | mlock2 | sys_mlock2 | 3 | unsigned long start | size_t len | int flags | - | - | - | - |
323 | copy_file_range | sys_copy_file_range | 6 | int fd_in | loff_t __user * off_in | int fd_out | loff_t __user * off_out | size_t len | unsigned int flags | - |
324 | preadv2 | sys_preadv2 | 6 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | rwf_t flags | - |
325 | pwritev2 | sys_pwritev2 | 6 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | rwf_t flags | - |
326 | statx | sys_statx | 5 | int dfd | const char __user * filename | unsigned flags | unsigned int mask | struct statx __user * buffer | - | - |
327 | io_pgetevents | sys_io_pgetevents | 6 | aio_context_t ctx_id | long min_nr | long nr | struct io_event __user * events | struct __kernel_timespec __user * timeout | const struct __aio_sigset __user * usig | - |
328 | perf_event_open | sys_perf_event_open | 5 | struct perf_event_attr __user * attr_uptr | pid_t pid | int cpu | int group_fd | unsigned long flags | - | - |
329 | seccomp | sys_seccomp | 3 | unsigned int op | unsigned int flags | void __user * uargs | - | - | - | - |
330 | pkey_mprotect | sys_pkey_mprotect | 4 | unsigned long start | size_t len | unsigned long prot | int pkey | - | - | - |
331 | pkey_alloc | sys_pkey_alloc | 2 | unsigned long flags | unsigned long init_val | - | - | - | - | - |
332 | pkey_free | sys_pkey_free | 1 | int pkey | - | - | - | - | - | - |
333 | rseq | sys_rseq | 4 | struct rseq __user * rseq | u32 rseq_len | int flags | u32 sig | - | - | - |
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
436 | close_range | sys_close_range | 3 | unsigned int fd | unsigned int max_fd | unsigned int flags | - | - | - | - |
437 | openat2 | sys_openat2 | 4 | int dfd | const char __user * filename | struct open_how __user * how | size_t usize | - | - | - |
438 | pidfd_getfd | sys_pidfd_getfd | 3 | int pidfd | int fd | unsigned int flags | - | - | - | - |
439 | faccessat2 | sys_faccessat2 | 4 | int dfd | const char __user * filename | int mode | int flags | - | - | - |
440 | process_madvise | sys_process_madvise | 5 | int pidfd | const struct iovec __user * vec | size_t vlen | int behavior | unsigned int flags | - | - |
441 | epoll_pwait2 | sys_epoll_pwait2 | 6 | int epfd | struct epoll_event __user * events | int maxevents | const struct __kernel_timespec __user * timeout | const sigset_t __user * sigmask | size_t sigsetsize | - |
442 | mount_setattr | sys_mount_setattr | 5 | int dfd | const char __user * path | unsigned int flags | struct mount_attr __user * uattr | size_t usize | - | - |
443 | quotactl_fd | sys_quotactl_fd | 4 | unsigned int fd | unsigned int cmd | qid_t id | void __user * addr | - | - | - |
445 | landlock_add_rule | sys_landlock_add_rule | 4 | const int ruleset_fd | const enum landlock_rule_type rule_type | const void __user *const rule_attr | const __u32 flags | - | - | - |
446 | landlock_restrict_self | sys_landlock_restrict_self | 2 | const int ruleset_fd | const __u32 flags | - | - | - | - | - |
448 | process_mrelease | sys_process_mrelease | 2 | int pidfd | unsigned int flags | - | - | - | - | - |
449 | futex_waitv | sys_futex_waitv | 5 | struct futex_waitv __user * waiters | unsigned int nr_futexes | unsigned int flags | struct __kernel_timespec __user * timeout | clockid_t clockid | - | - |
