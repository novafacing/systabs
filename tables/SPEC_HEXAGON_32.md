
#  hexagon 32-bit

| Syscall # | Name | Entry Points | # Arguments | arg0 | arg1 | arg2 | arg3 | arg4 | arg5 | arg6 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
0 | io_setup |  | 2 | unsigned nr_events | aio_context_t __user * ctxp | - | - | - | - | - |
1 | io_destroy |  | 1 | aio_context_t ctx | - | - | - | - | - | - |
2 | io_submit |  | 3 | aio_context_t ctx_id | long nr | struct iocb __user * __user * iocbpp | - | - | - | - |
3 | io_cancel |  | 3 | aio_context_t ctx_id | struct iocb __user * iocb | struct io_event __user * result | - | - | - | - |
4 | io_getevents |  | 5 | aio_context_t ctx_id | long min_nr | long nr | struct io_event __user * events | struct __kernel_timespec __user * timeout | - | - |
5 | setxattr |  | 5 | const char __user * pathname | const char __user * name | const void __user * value | size_t size | int flags | - | - |
6 | lsetxattr |  | 5 | const char __user * pathname | const char __user * name | const void __user * value | size_t size | int flags | - | - |
7 | fsetxattr |  | 5 | int fd | const char __user * name | const void __user * value | size_t size | int flags | - | - |
8 | getxattr |  | 4 | const char __user * pathname | const char __user * name | void __user * value | size_t size | - | - | - |
9 | lgetxattr |  | 4 | const char __user * pathname | const char __user * name | void __user * value | size_t size | - | - | - |
10 | fgetxattr |  | 4 | int fd | const char __user * name | void __user * value | size_t size | - | - | - |
11 | listxattr |  | 3 | const char __user * pathname | char __user * list | size_t size | - | - | - | - |
12 | llistxattr |  | 3 | const char __user * pathname | char __user * list | size_t size | - | - | - | - |
13 | flistxattr |  | 3 | int fd | char __user * list | size_t size | - | - | - | - |
14 | removexattr |  | 2 | const char __user * pathname | const char __user * name | - | - | - | - | - |
15 | lremovexattr |  | 2 | const char __user * pathname | const char __user * name | - | - | - | - | - |
16 | fremovexattr |  | 2 | int fd | const char __user * name | - | - | - | - | - |
17 | getcwd |  | 2 | char __user * buf | unsigned long size | - | - | - | - | - |
19 | eventfd2 |  | 2 | unsigned int count | int flags | - | - | - | - | - |
20 | epoll_create1 |  | 1 | int flags | - | - | - | - | - | - |
21 | epoll_ctl |  | 4 | int epfd | int op | int fd | struct epoll_event __user * event | - | - | - |
22 | epoll_pwait |  | 6 | int epfd | struct epoll_event __user * events | int maxevents | int timeout | const sigset_t __user * sigmask | size_t sigsetsize | - |
23 | dup |  | 1 | unsigned int fildes | - | - | - | - | - | - |
24 | dup3 |  | 3 | unsigned int oldfd | unsigned int newfd | int flags | - | - | - | - |
25 | fcntl |  | 3 | unsigned int fd | unsigned int cmd | unsigned long arg | - | - | - | - |
26 | inotify_init1 |  | 1 | int flags | - | - | - | - | - | - |
27 | inotify_add_watch |  | 3 | int fd | const char __user * pathname | u32 mask | - | - | - | - |
28 | inotify_rm_watch |  | 2 | int fd | __s32 wd | - | - | - | - | - |
29 | ioctl |  | 3 | unsigned int fd | unsigned int cmd | unsigned long arg | - | - | - | - |
30 | ioprio_set |  | 3 | int which | int who | int ioprio | - | - | - | - |
31 | ioprio_get |  | 2 | int which | int who | - | - | - | - | - |
32 | flock |  | 2 | unsigned int fd | unsigned int cmd | - | - | - | - | - |
33 | mknodat |  | 4 | int dfd | const char __user * filename | umode_t mode | unsigned int dev | - | - | - |
34 | mkdirat |  | 3 | int dfd | const char __user * pathname | umode_t mode | - | - | - | - |
35 | unlinkat |  | 3 | int dfd | const char __user * pathname | int flag | - | - | - | - |
36 | symlinkat |  | 3 | const char __user * oldname | int newdfd | const char __user * newname | - | - | - | - |
37 | linkat |  | 5 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | int flags | - | - |
40 | mount |  | 5 | char __user * dev_name | char __user * dir_name | char __user * type | unsigned long flags | void __user * data | - | - |
41 | pivot_root |  | 2 | const char __user * new_root | const char __user * put_old | - | - | - | - | - |
43 | statfs |  | 2 | const char __user * pathname | struct statfs __user * buf | - | - | - | - | - |
44 | fstatfs |  | 2 | unsigned int fd | struct statfs __user * buf | - | - | - | - | - |
45 | truncate |  | 2 | const char __user * path | long length | - | - | - | - | - |
46 | ftruncate |  | 2 | unsigned int fd | unsigned long length | - | - | - | - | - |
47 | fallocate |  | 4 | int fd | int mode | loff_t offset | loff_t len | - | - | - |
48 | faccessat |  | 3 | int dfd | const char __user * filename | int mode | - | - | - | - |
49 | chdir |  | 1 | const char __user * filename | - | - | - | - | - | - |
50 | fchdir |  | 1 | unsigned int fd | - | - | - | - | - | - |
51 | chroot |  | 1 | const char __user * filename | - | - | - | - | - | - |
52 | fchmod |  | 2 | unsigned int fd | umode_t mode | - | - | - | - | - |
53 | fchmodat |  | 3 | int dfd | const char __user * filename | umode_t mode | - | - | - | - |
54 | fchownat |  | 5 | int dfd | const char __user * filename | uid_t user | gid_t group | int flag | - | - |
55 | fchown |  | 3 | unsigned int fd | uid_t user | gid_t group | - | - | - | - |
56 | openat |  | 4 | int dfd | const char __user * filename | int flags | umode_t mode | - | - | - |
57 | close |  | 1 | unsigned int fd | - | - | - | - | - | - |
58 | vhangup |  | 0 | - | - | - | - | - | - | - |
59 | pipe2 |  | 2 | int __user * fildes | int flags | - | - | - | - | - |
60 | quotactl |  | 4 | unsigned int cmd | const char __user * special | qid_t id | void __user * addr | - | - | - |
61 | getdents64 |  | 3 | unsigned int fd | struct linux_dirent64 __user * dirent | unsigned int count | - | - | - | - |
62 | lseek |  | 3 | unsigned int fd | off_t offset | unsigned int whence | - | - | - | - |
63 | read |  | 3 | unsigned int fd | char __user * buf | size_t count | - | - | - | - |
64 | write |  | 3 | unsigned int fd | const char __user * buf | size_t count | - | - | - | - |
65 | readv |  | 3 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | - | - | - | - |
66 | writev |  | 3 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | - | - | - | - |
67 | pread64 |  | 4 | unsigned int fd | char __user * buf | size_t count | loff_t pos | - | - | - |
68 | pwrite64 |  | 4 | unsigned int fd | const char __user * buf | size_t count | loff_t pos | - | - | - |
69 | preadv |  | 5 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | - | - |
70 | pwritev |  | 5 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | - | - |
71 | sendfile |  | 4 | int out_fd | int in_fd | off_t __user * offset | size_t count | - | - | - |
72 | pselect6 |  | 6 | int n | fd_set __user * inp | fd_set __user * outp | fd_set __user * exp | struct __kernel_timespec __user * tsp | void __user * sig | - |
73 | ppoll |  | 5 | struct pollfd __user * ufds | unsigned int nfds | struct __kernel_timespec __user * tsp | const sigset_t __user * sigmask | size_t sigsetsize | - | - |
74 | signalfd4 |  | 4 | int ufd | sigset_t __user * user_mask | size_t sizemask | int flags | - | - | - |
75 | vmsplice |  | 4 | int fd | const struct iovec __user * uiov | unsigned long nr_segs | unsigned int flags | - | - | - |
76 | splice |  | 6 | int fd_in | loff_t __user * off_in | int fd_out | loff_t __user * off_out | size_t len | unsigned int flags | - |
77 | tee |  | 4 | int fdin | int fdout | size_t len | unsigned int flags | - | - | - |
78 | readlinkat |  | 4 | int dfd | const char __user * pathname | char __user * buf | int bufsiz | - | - | - |
81 | sync |  | 0 | - | - | - | - | - | - | - |
82 | fsync |  | 1 | unsigned int fd | - | - | - | - | - | - |
83 | fdatasync |  | 1 | unsigned int fd | - | - | - | - | - | - |
84 | sync_file_range |  | 4 | int fd | loff_t offset | loff_t nbytes | unsigned int flags | - | - | - |
85 | timerfd_create |  | 2 | int clockid | int flags | - | - | - | - | - |
86 | timerfd_settime |  | 4 | int ufd | int flags | const struct __kernel_itimerspec __user * utmr | struct __kernel_itimerspec __user * otmr | - | - | - |
87 | timerfd_gettime |  | 2 | int ufd | struct __kernel_itimerspec __user * otmr | - | - | - | - | - |
88 | utimensat |  | 4 | int dfd | const char __user * filename | struct __kernel_timespec __user * utimes | int flags | - | - | - |
89 | acct |  | 1 | const char __user * name | - | - | - | - | - | - |
90 | capget |  | 2 | cap_user_header_t header | cap_user_data_t dataptr | - | - | - | - | - |
91 | capset |  | 2 | cap_user_header_t header | const cap_user_data_t data | - | - | - | - | - |
92 | personality |  | 1 | unsigned int personality | - | - | - | - | - | - |
93 | exit |  | 1 | int error_code | - | - | - | - | - | - |
94 | exit_group |  | 1 | int error_code | - | - | - | - | - | - |
96 | set_tid_address |  | 1 | int __user * tidptr | - | - | - | - | - | - |
97 | unshare |  | 1 | unsigned long unshare_flags | - | - | - | - | - | - |
98 | futex |  | 6 | u32 __user * uaddr | int op | u32 val | const struct __kernel_timespec __user * utime | u32 __user * uaddr2 | u32 val3 | - |
99 | set_robust_list |  | 2 | struct robust_list_head __user * head | size_t len | - | - | - | - | - |
100 | get_robust_list |  | 3 | int pid | struct robust_list_head __user * __user * head_ptr | size_t __user * len_ptr | - | - | - | - |
101 | nanosleep |  | 2 | struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - | - | - |
102 | getitimer |  | 2 | int which | struct __kernel_old_itimerval __user * value | - | - | - | - | - |
103 | setitimer |  | 3 | int which | struct __kernel_old_itimerval __user * value | struct __kernel_old_itimerval __user * ovalue | - | - | - | - |
104 | kexec_load |  | 4 | unsigned long entry | unsigned long nr_segments | struct kexec_segment __user * segments | unsigned long flags | - | - | - |
105 | init_module |  | 3 | void __user * umod | unsigned long len | const char __user * uargs | - | - | - | - |
106 | delete_module |  | 2 | const char __user * name_user | unsigned int flags | - | - | - | - | - |
107 | timer_create |  | 3 | const clockid_t which_clock | struct sigevent __user * timer_event_spec | timer_t __user * created_timer_id | - | - | - | - |
108 | timer_gettime |  | 2 | timer_t timer_id | struct __kernel_itimerspec __user * setting | - | - | - | - | - |
109 | timer_getoverrun |  | 1 | timer_t timer_id | - | - | - | - | - | - |
110 | timer_settime |  | 4 | timer_t timer_id | int flags | const struct __kernel_itimerspec __user * new_setting | struct __kernel_itimerspec __user * old_setting | - | - | - |
111 | timer_delete |  | 1 | timer_t timer_id | - | - | - | - | - | - |
112 | clock_settime |  | 2 | const clockid_t which_clock | const struct __kernel_timespec __user * tp | - | - | - | - | - |
112 | clock_settime |  | 2 | const clockid_t which_clock | const struct __kernel_timespec __user * tp | - | - | - | - | - |
113 | clock_gettime |  | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
113 | clock_gettime |  | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
114 | clock_getres |  | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
114 | clock_getres |  | 2 | const clockid_t which_clock | struct __kernel_timespec __user * tp | - | - | - | - | - |
115 | clock_nanosleep |  | 4 | const clockid_t which_clock | int flags | const struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - |
115 | clock_nanosleep |  | 4 | const clockid_t which_clock | int flags | const struct __kernel_timespec __user * rqtp | struct __kernel_timespec __user * rmtp | - | - | - |
116 | syslog |  | 3 | int type | char __user * buf | int len | - | - | - | - |
117 | ptrace |  | 4 | long request | long pid | unsigned long addr | unsigned long data | - | - | - |
118 | sched_setparam |  | 2 | pid_t pid | struct sched_param __user * param | - | - | - | - | - |
119 | sched_setscheduler |  | 3 | pid_t pid | int policy | struct sched_param __user * param | - | - | - | - |
120 | sched_getscheduler |  | 1 | pid_t pid | - | - | - | - | - | - |
121 | sched_getparam |  | 2 | pid_t pid | struct sched_param __user * param | - | - | - | - | - |
122 | sched_setaffinity |  | 3 | pid_t pid | unsigned int len | unsigned long __user * user_mask_ptr | - | - | - | - |
123 | sched_getaffinity |  | 3 | pid_t pid | unsigned int len | unsigned long __user * user_mask_ptr | - | - | - | - |
124 | sched_yield |  | 0 | - | - | - | - | - | - | - |
125 | sched_get_priority_max |  | 1 | int policy | - | - | - | - | - | - |
126 | sched_get_priority_min |  | 1 | int policy | - | - | - | - | - | - |
127 | sched_rr_get_interval |  | 2 | pid_t pid | struct __kernel_timespec __user * interval | - | - | - | - | - |
128 | restart_syscall |  | 0 | - | - | - | - | - | - | - |
129 | kill |  | 2 | pid_t pid | int sig | - | - | - | - | - |
130 | tkill |  | 2 | pid_t pid | int sig | - | - | - | - | - |
131 | tgkill |  | 3 | pid_t tgid | pid_t pid | int sig | - | - | - | - |
132 | sigaltstack |  | 2 | const stack_t __user * uss | stack_t __user * uoss | - | - | - | - | - |
133 | rt_sigsuspend |  | 2 | sigset_t __user * unewset | size_t sigsetsize | - | - | - | - | - |
135 | rt_sigprocmask |  | 4 | int how | sigset_t __user * nset | sigset_t __user * oset | size_t sigsetsize | - | - | - |
136 | rt_sigpending |  | 2 | sigset_t __user * uset | size_t sigsetsize | - | - | - | - | - |
137 | rt_sigtimedwait |  | 4 | const sigset_t __user * uthese | siginfo_t __user * uinfo | const struct __kernel_timespec __user * uts | size_t sigsetsize | - | - | - |
138 | rt_sigqueueinfo |  | 3 | pid_t pid | int sig | siginfo_t __user * uinfo | - | - | - | - |
140 | setpriority |  | 3 | int which | int who | int niceval | - | - | - | - |
141 | getpriority |  | 2 | int which | int who | - | - | - | - | - |
142 | reboot |  | 4 | int magic1 | int magic2 | unsigned int cmd | void __user * arg | - | - | - |
143 | setregid |  | 2 | gid_t rgid | gid_t egid | - | - | - | - | - |
144 | setgid |  | 1 | gid_t gid | - | - | - | - | - | - |
145 | setreuid |  | 2 | uid_t ruid | uid_t euid | - | - | - | - | - |
146 | setuid |  | 1 | uid_t uid | - | - | - | - | - | - |
147 | setresuid |  | 3 | uid_t ruid | uid_t euid | uid_t suid | - | - | - | - |
148 | getresuid |  | 3 | uid_t __user * ruidp | uid_t __user * euidp | uid_t __user * suidp | - | - | - | - |
149 | setresgid |  | 3 | gid_t rgid | gid_t egid | gid_t sgid | - | - | - | - |
150 | getresgid |  | 3 | gid_t __user * rgidp | gid_t __user * egidp | gid_t __user * sgidp | - | - | - | - |
151 | setfsuid |  | 1 | uid_t uid | - | - | - | - | - | - |
152 | setfsgid |  | 1 | gid_t gid | - | - | - | - | - | - |
153 | times |  | 1 | struct tms __user * tbuf | - | - | - | - | - | - |
154 | setpgid |  | 2 | pid_t pid | pid_t pgid | - | - | - | - | - |
155 | getpgid |  | 1 | pid_t pid | - | - | - | - | - | - |
156 | getsid |  | 1 | pid_t pid | - | - | - | - | - | - |
157 | setsid |  | 0 | - | - | - | - | - | - | - |
158 | getgroups |  | 2 | int gidsetsize | gid_t __user * grouplist | - | - | - | - | - |
159 | setgroups |  | 2 | int gidsetsize | gid_t __user * grouplist | - | - | - | - | - |
160 | uname |  | 1 | struct old_utsname __user * name | - | - | - | - | - | - |
161 | sethostname |  | 2 | char __user * name | int len | - | - | - | - | - |
162 | setdomainname |  | 2 | char __user * name | int len | - | - | - | - | - |
165 | getrusage |  | 2 | int who | struct rusage __user * ru | - | - | - | - | - |
169 | gettimeofday |  | 2 | struct __kernel_old_timeval __user * tv | struct timezone __user * tz | - | - | - | - | - |
170 | settimeofday |  | 2 | struct __kernel_old_timeval __user * tv | struct timezone __user * tz | - | - | - | - | - |
171 | adjtimex |  | 1 | struct __kernel_timex __user * txc_p | - | - | - | - | - | - |
172 | getpid |  | 0 | - | - | - | - | - | - | - |
173 | getppid |  | 0 | - | - | - | - | - | - | - |
174 | getuid |  | 0 | - | - | - | - | - | - | - |
175 | geteuid |  | 0 | - | - | - | - | - | - | - |
176 | getgid |  | 0 | - | - | - | - | - | - | - |
177 | getegid |  | 0 | - | - | - | - | - | - | - |
178 | gettid |  | 0 | - | - | - | - | - | - | - |
180 | mq_open |  | 4 | const char __user * u_name | int oflag | umode_t mode | struct mq_attr __user * u_attr | - | - | - |
181 | mq_unlink |  | 1 | const char __user * u_name | - | - | - | - | - | - |
182 | mq_timedsend |  | 5 | mqd_t mqdes | const char __user * u_msg_ptr | size_t msg_len | unsigned int msg_prio | const struct __kernel_timespec __user * u_abs_timeout | - | - |
183 | mq_timedreceive |  | 5 | mqd_t mqdes | char __user * u_msg_ptr | size_t msg_len | unsigned int __user * u_msg_prio | const struct __kernel_timespec __user * u_abs_timeout | - | - |
186 | msgget |  | 2 | key_t key | int msgflg | - | - | - | - | - |
187 | msgctl |  | 3 | int msqid | int cmd | struct msqid_ds __user * buf | - | - | - | - |
188 | msgrcv |  | 5 | int msqid | struct msgbuf __user * msgp | size_t msgsz | long msgtyp | int msgflg | - | - |
189 | msgsnd |  | 4 | int msqid | struct msgbuf __user * msgp | size_t msgsz | int msgflg | - | - | - |
190 | semget |  | 3 | key_t key | int nsems | int semflg | - | - | - | - |
191 | semctl |  | 4 | int semid | int semnum | int cmd | unsigned long arg | - | - | - |
192 | semtimedop |  | 4 | int semid | struct sembuf __user * tsops | unsigned int nsops | const struct __kernel_timespec __user * timeout | - | - | - |
193 | semop |  | 3 | int semid | struct sembuf __user * tsops | unsigned nsops | - | - | - | - |
194 | shmget |  | 3 | key_t key | size_t size | int shmflg | - | - | - | - |
195 | shmctl |  | 3 | int shmid | int cmd | struct shmid_ds __user * buf | - | - | - | - |
196 | shmat |  | 3 | int shmid | char __user * shmaddr | int shmflg | - | - | - | - |
197 | shmdt |  | 1 | char __user * shmaddr | - | - | - | - | - | - |
198 | socket |  | 3 | int family | int type | int protocol | - | - | - | - |
199 | socketpair |  | 4 | int family | int type | int protocol | int __user * usockvec | - | - | - |
200 | bind |  | 3 | int fd | struct sockaddr __user * umyaddr | int addrlen | - | - | - | - |
201 | listen |  | 2 | int fd | int backlog | - | - | - | - | - |
202 | accept |  | 3 | int fd | struct sockaddr __user * upeer_sockaddr | int __user * upeer_addrlen | - | - | - | - |
203 | connect |  | 3 | int fd | struct sockaddr __user * uservaddr | int addrlen | - | - | - | - |
204 | getsockname |  | 3 | int fd | struct sockaddr __user * usockaddr | int __user * usockaddr_len | - | - | - | - |
205 | getpeername |  | 3 | int fd | struct sockaddr __user * usockaddr | int __user * usockaddr_len | - | - | - | - |
206 | sendto |  | 6 | int fd | void __user * buff | size_t len | unsigned int flags | struct sockaddr __user * addr | int addr_len | - |
207 | recvfrom |  | 6 | int fd | void __user * ubuf | size_t size | unsigned int flags | struct sockaddr __user * addr | int __user * addr_len | - |
208 | setsockopt |  | 5 | int fd | int level | int optname | char __user * optval | int optlen | - | - |
209 | getsockopt |  | 5 | int fd | int level | int optname | char __user * optval | int __user * optlen | - | - |
210 | shutdown |  | 2 | int fd | int how | - | - | - | - | - |
211 | sendmsg |  | 3 | int fd | struct user_msghdr __user * msg | unsigned int flags | - | - | - | - |
212 | recvmsg |  | 3 | int fd | struct user_msghdr __user * msg | unsigned int flags | - | - | - | - |
213 | readahead |  | 3 | int fd | loff_t offset | size_t count | - | - | - | - |
214 | brk |  | 1 | unsigned long brk | - | - | - | - | - | - |
214 | brk |  | 1 | unsigned long brk | - | - | - | - | - | - |
215 | munmap |  | 2 | unsigned long addr | size_t len | - | - | - | - | - |
215 | munmap |  | 2 | unsigned long addr | size_t len | - | - | - | - | - |
216 | mremap |  | 5 | unsigned long addr | unsigned long old_len | unsigned long new_len | unsigned long flags | unsigned long new_addr | - | - |
216 | mremap |  | 5 | unsigned long addr | unsigned long old_len | unsigned long new_len | unsigned long flags | unsigned long new_addr | - | - |
217 | add_key |  | 5 | const char __user * _type | const char __user * _description | const void __user * _payload | size_t plen | key_serial_t ringid | - | - |
218 | request_key |  | 4 | const char __user * _type | const char __user * _description | const char __user * _callout_info | key_serial_t destringid | - | - | - |
219 | keyctl |  | 5 | int option | unsigned long arg2 | unsigned long arg3 | unsigned long arg4 | unsigned long arg5 | - | - |
220 | clone |  | 5 | unsigned long clone_flags | unsigned long newsp | int __user * parent_tidptr | unsigned long tls | int __user * child_tidptr | - | - |
220 | clone |  | 5 | unsigned long newsp | unsigned long clone_flags | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - | - |
220 | clone |  | 6 | unsigned long clone_flags | unsigned long newsp | int stack_size | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - |
220 | clone |  | 5 | unsigned long clone_flags | unsigned long newsp | int __user * parent_tidptr | int __user * child_tidptr | unsigned long tls | - | - |
221 | execve |  | 3 | const char __user * filename | const char __user *const __user * argv | const char __user *const __user * envp | - | - | - | - |
223 | fadvise64 |  | 4 | int fd | loff_t offset | size_t len | int advice | - | - | - |
224 | swapon |  | 2 | const char __user * specialfile | int swap_flags | - | - | - | - | - |
225 | swapoff |  | 1 | const char __user * specialfile | - | - | - | - | - | - |
226 | mprotect |  | 3 | unsigned long start | size_t len | unsigned long prot | - | - | - | - |
227 | msync |  | 3 | unsigned long start | size_t len | int flags | - | - | - | - |
228 | mlock |  | 2 | unsigned long start | size_t len | - | - | - | - | - |
229 | munlock |  | 2 | unsigned long start | size_t len | - | - | - | - | - |
230 | mlockall |  | 1 | int flags | - | - | - | - | - | - |
231 | munlockall |  | 0 | - | - | - | - | - | - | - |
232 | mincore |  | 3 | unsigned long start | size_t len | unsigned char __user * vec | - | - | - | - |
233 | madvise |  | 3 | unsigned long start | size_t len_in | int behavior | - | - | - | - |
234 | remap_file_pages |  | 5 | unsigned long start | unsigned long size | unsigned long prot | unsigned long pgoff | unsigned long flags | - | - |
235 | mbind |  | 6 | unsigned long start | unsigned long len | unsigned long mode | const unsigned long __user * nmask | unsigned long maxnode | unsigned int flags | - |
236 | get_mempolicy |  | 5 | int __user * policy | unsigned long __user * nmask | unsigned long maxnode | unsigned long addr | unsigned long flags | - | - |
237 | set_mempolicy |  | 3 | int mode | const unsigned long __user * nmask | unsigned long maxnode | - | - | - | - |
238 | migrate_pages |  | 4 | pid_t pid | unsigned long maxnode | const unsigned long __user * old_nodes | const unsigned long __user * new_nodes | - | - | - |
239 | move_pages |  | 6 | pid_t pid | unsigned long nr_pages | const void __user * __user * pages | const int __user * nodes | int __user * status | int flags | - |
240 | rt_tgsigqueueinfo |  | 4 | pid_t tgid | pid_t pid | int sig | siginfo_t __user * uinfo | - | - | - |
241 | perf_event_open |  | 5 | struct perf_event_attr __user * attr_uptr | pid_t pid | int cpu | int group_fd | unsigned long flags | - | - |
242 | accept4 |  | 4 | int fd | struct sockaddr __user * upeer_sockaddr | int __user * upeer_addrlen | int flags | - | - | - |
243 | recvmmsg |  | 5 | int fd | struct mmsghdr __user * mmsg | unsigned int vlen | unsigned int flags | struct __kernel_timespec __user * timeout | - | - |
261 | prlimit64 |  | 4 | pid_t pid | unsigned int resource | const struct rlimit64 __user * new_rlim | struct rlimit64 __user * old_rlim | - | - | - |
262 | fanotify_init |  | 2 | unsigned int flags | unsigned int event_f_flags | - | - | - | - | - |
263 | fanotify_mark |  | 5 | int fanotify_fd | unsigned int flags | __u64 mask | int dfd | const char __user * pathname | - | - |
264 | name_to_handle_at |  | 5 | int dfd | const char __user * name | struct file_handle __user * handle | int __user * mnt_id | int flag | - | - |
265 | open_by_handle_at |  | 3 | int mountdirfd | struct file_handle __user * handle | int flags | - | - | - | - |
266 | clock_adjtime |  | 2 | const clockid_t which_clock | struct __kernel_timex __user * utx | - | - | - | - | - |
267 | syncfs |  | 1 | int fd | - | - | - | - | - | - |
268 | setns |  | 2 | int fd | int flags | - | - | - | - | - |
269 | sendmmsg |  | 4 | int fd | struct mmsghdr __user * mmsg | unsigned int vlen | unsigned int flags | - | - | - |
270 | process_vm_readv |  | 6 | pid_t pid | const struct iovec __user * lvec | unsigned long liovcnt | const struct iovec __user * rvec | unsigned long riovcnt | unsigned long flags | - |
271 | process_vm_writev |  | 6 | pid_t pid | const struct iovec __user * lvec | unsigned long liovcnt | const struct iovec __user * rvec | unsigned long riovcnt | unsigned long flags | - |
272 | kcmp |  | 5 | pid_t pid1 | pid_t pid2 | int type | unsigned long idx1 | unsigned long idx2 | - | - |
273 | finit_module |  | 3 | int fd | const char __user * uargs | int flags | - | - | - | - |
274 | sched_setattr |  | 3 | pid_t pid | struct sched_attr __user * uattr | unsigned int flags | - | - | - | - |
275 | sched_getattr |  | 4 | pid_t pid | struct sched_attr __user * uattr | unsigned int usize | unsigned int flags | - | - | - |
276 | renameat2 |  | 5 | int olddfd | const char __user * oldname | int newdfd | const char __user * newname | unsigned int flags | - | - |
277 | seccomp |  | 3 | unsigned int op | unsigned int flags | void __user * uargs | - | - | - | - |
278 | getrandom |  | 3 | char __user * buf | size_t count | unsigned int flags | - | - | - | - |
279 | memfd_create |  | 2 | const char __user * uname | unsigned int flags | - | - | - | - | - |
280 | bpf |  | 3 | int cmd | union bpf_attr __user * uattr | unsigned int size | - | - | - | - |
281 | execveat |  | 5 | int fd | const char __user * filename | const char __user *const __user * argv | const char __user *const __user * envp | int flags | - | - |
282 | userfaultfd |  | 1 | int flags | - | - | - | - | - | - |
283 | membarrier |  | 3 | int cmd | unsigned int flags | int cpu_id | - | - | - | - |
284 | mlock2 |  | 3 | unsigned long start | size_t len | int flags | - | - | - | - |
285 | copy_file_range |  | 6 | int fd_in | loff_t __user * off_in | int fd_out | loff_t __user * off_out | size_t len | unsigned int flags | - |
286 | preadv2 |  | 6 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | rwf_t flags | - |
287 | pwritev2 |  | 6 | unsigned long fd | const struct iovec __user * vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | rwf_t flags | - |
288 | pkey_mprotect |  | 4 | unsigned long start | size_t len | unsigned long prot | int pkey | - | - | - |
289 | pkey_alloc |  | 2 | unsigned long flags | unsigned long init_val | - | - | - | - | - |
290 | pkey_free |  | 1 | int pkey | - | - | - | - | - | - |
291 | statx |  | 5 | int dfd | const char __user * filename | unsigned flags | unsigned int mask | struct statx __user * buffer | - | - |
292 | io_pgetevents |  | 6 | aio_context_t ctx_id | long min_nr | long nr | struct io_event __user * events | struct __kernel_timespec __user * timeout | const struct __aio_sigset __user * usig | - |
293 | rseq |  | 4 | struct rseq __user * rseq | u32 rseq_len | int flags | u32 sig | - | - | - |
294 | kexec_file_load |  | 5 | int kernel_fd | int initrd_fd | unsigned long cmdline_len | const char __user * cmdline_ptr | unsigned long flags | - | - |
424 | pidfd_send_signal |  | 4 | int pidfd | int sig | siginfo_t __user * info | unsigned int flags | - | - | - |
425 | io_uring_setup |  | 2 | u32 entries | struct io_uring_params __user * params | - | - | - | - | - |
426 | io_uring_enter |  | 6 | unsigned int fd | u32 to_submit | u32 min_complete | u32 flags | const void __user * argp | size_t argsz | - |
427 | io_uring_register |  | 4 | unsigned int fd | unsigned int opcode | void __user * arg | unsigned int nr_args | - | - | - |
428 | open_tree |  | 3 | int dfd | const char __user * filename | unsigned flags | - | - | - | - |
429 | move_mount |  | 5 | int from_dfd | const char __user * from_pathname | int to_dfd | const char __user * to_pathname | unsigned int flags | - | - |
430 | fsopen |  | 2 | const char __user * _fs_name | unsigned int flags | - | - | - | - | - |
431 | fsconfig |  | 5 | int fd | unsigned int cmd | const char __user * _key | const void __user * _value | int aux | - | - |
432 | fsmount |  | 3 | int fs_fd | unsigned int flags | unsigned int attr_flags | - | - | - | - |
433 | fspick |  | 3 | int dfd | const char __user * path | unsigned int flags | - | - | - | - |
434 | pidfd_open |  | 2 | pid_t pid | unsigned int flags | - | - | - | - | - |
436 | close_range |  | 3 | unsigned int fd | unsigned int max_fd | unsigned int flags | - | - | - | - |
437 | openat2 |  | 4 | int dfd | const char __user * filename | struct open_how __user * how | size_t usize | - | - | - |
438 | pidfd_getfd |  | 3 | int pidfd | int fd | unsigned int flags | - | - | - | - |
439 | faccessat2 |  | 4 | int dfd | const char __user * filename | int mode | int flags | - | - | - |
440 | process_madvise |  | 5 | int pidfd | const struct iovec __user * vec | size_t vlen | int behavior | unsigned int flags | - | - |
441 | epoll_pwait2 |  | 6 | int epfd | struct epoll_event __user * events | int maxevents | const struct __kernel_timespec __user * timeout | const sigset_t __user * sigmask | size_t sigsetsize | - |
442 | mount_setattr |  | 5 | int dfd | const char __user * path | unsigned int flags | struct mount_attr __user * uattr | size_t usize | - | - |
443 | quotactl_fd |  | 4 | unsigned int fd | unsigned int cmd | qid_t id | void __user * addr | - | - | - |
445 | landlock_add_rule |  | 4 | const int ruleset_fd | const enum landlock_rule_type rule_type | const void __user *const rule_attr | const __u32 flags | - | - | - |
446 | landlock_restrict_self |  | 2 | const int ruleset_fd | const __u32 flags | - | - | - | - | - |
448 | process_mrelease |  | 2 | int pidfd | unsigned int flags | - | - | - | - | - |
449 | futex_waitv |  | 5 | struct futex_waitv __user * waiters | unsigned int nr_futexes | unsigned int flags | struct __kernel_timespec __user * timeout | clockid_t clockid | - | - |
