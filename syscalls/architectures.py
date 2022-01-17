from enum import Enum


class ARCHITECTURE(str, Enum):
    """
    Default Linux Architecture List
    """

    alpha = "alpha"  # pylint: disable=invalid-name
    arc = "arc"  # pylint: disable=invalid-name
    arm = "arm"  # pylint: disable=invalid-name
    arm64 = "arm64"  # pylint: disable=invalid-name
    csky = "csky"  # pylint: disable=invalid-name
    h8300 = "h8300"  # pylint: disable=invalid-name
    hexagon = "hexagon"  # pylint: disable=invalid-name
    ia64 = "ia64"  # pylint: disable=invalid-name
    m68k = "m68k"  # pylint: disable=invalid-name
    microblaze = "microblaze"  # pylint: disable=invalid-name
    mips = "mips"  # pylint: disable=invalid-name
    nds32 = "nds32"  # pylint: disable=invalid-name
    nios2 = "nios2"  # pylint: disable=invalid-name
    openrisc = "openrisc"  # pylint: disable=invalid-name
    parisc = "parisc"  # pylint: disable=invalid-name
    powerpc = "powerpc"  # pylint: disable=invalid-name
    riscv = "riscv"  # pylint: disable=invalid-name
    s390 = "s390"  # pylint: disable=invalid-name
    sparc = "sparc"  # pylint: disable=invalid-name
    x86 = "x86"  # pylint: disable=invalid-name
    xtensa = "xtensa"  # pylint: disable=invalid-name


ALL_ARCHES = (
    (ARCHITECTURE.alpha, 64),
    (ARCHITECTURE.arc, 32),
    (ARCHITECTURE.arc, 64),
    (ARCHITECTURE.arm, 32),
    (ARCHITECTURE.arm64, 64),
    (ARCHITECTURE.csky, 32),
    (ARCHITECTURE.h8300, 16),
    (ARCHITECTURE.hexagon, 32),
    (ARCHITECTURE.ia64, 64),
    (ARCHITECTURE.m68k, 16),
    (ARCHITECTURE.m68k, 32),
    (ARCHITECTURE.microblaze, 32),
    (ARCHITECTURE.microblaze, 64),
    (ARCHITECTURE.mips, 32),
    (ARCHITECTURE.mips, 64),
    (ARCHITECTURE.nds32, 32),
    (ARCHITECTURE.nios2, 32),
    (ARCHITECTURE.openrisc, 32),
    (ARCHITECTURE.openrisc, 64),
    (ARCHITECTURE.parisc, 32),
    (ARCHITECTURE.parisc, 64),
    (ARCHITECTURE.powerpc, 32),
    (ARCHITECTURE.powerpc, 64),
    (ARCHITECTURE.riscv, 32),
    (ARCHITECTURE.riscv, 64),
    (ARCHITECTURE.s390, 32),
    (ARCHITECTURE.s390, 64),
    (ARCHITECTURE.sparc, 32),
    (ARCHITECTURE.sparc, 64),
    (ARCHITECTURE.x86, 32),
    (ARCHITECTURE.x86, 64),
    (ARCHITECTURE.xtensa, 32),
)

ARCH_SYSTAB = {
    ARCHITECTURE.alpha: {64: "arch/alpha/kernel/syscalls/syscall.tbl"},
    ARCHITECTURE.arc: {
        32: "",
        64: "",
    },
    ARCHITECTURE.arm: {
        32: "arch/arm/tools/syscall.tbl",
    },
    ARCHITECTURE.arm64: {
        64: "",
    },
    ARCHITECTURE.csky: {
        32: "",
    },
    ARCHITECTURE.h8300: {
        16: "",
    },
    ARCHITECTURE.hexagon: {
        32: "",
    },
    ARCHITECTURE.ia64: {
        64: "arch/ia64/kernel/syscalls/syscall.tbl",
    },
    ARCHITECTURE.m68k: {
        16: "arch/m68k/kernel/syscalls/syscall.tbl",
        32: "arch/m68k/kernel/syscalls/syscall.tbl",
    },
    ARCHITECTURE.microblaze: {
        32: "arch/microblaze/kernel/syscalls/syscall.tbl",
        64: "arch/microblaze/kernel/syscalls/syscall.tbl",
    },
    ARCHITECTURE.mips: {
        32: "arch/mips/kernel/syscalls/syscall_n32.tbl",
        64: "arch/mips/kernel/syscalls/syscall_n64.tbl",
    },
    ARCHITECTURE.nds32: {
        32: "",
    },
    ARCHITECTURE.nios2: {
        32: "",
    },
    ARCHITECTURE.openrisc: {
        32: "",
        64: "",
    },
    ARCHITECTURE.parisc: {
        32: "arch/parisc/kernel/syscalls/syscall.tbl",
        64: "arch/parisc/kernel/syscalls/syscall.tbl",
    },
    ARCHITECTURE.powerpc: {
        32: "arch/powerpc/kernel/syscalls/syscall.tbl",
        64: "arch/powerpc/kernel/syscalls/syscall.tbl",
    },
    ARCHITECTURE.riscv: {
        32: "",
        64: "",
    },
    ARCHITECTURE.s390: {
        32: "arch/s390/kernel/syscalls/syscall.tbl",
        64: "arch/s390/kernel/syscalls/syscall.tbl",
    },
    ARCHITECTURE.sparc: {
        32: "arch/sparc/kernel/syscalls/syscall.tbl",
        64: "arch/sparc/kernel/syscalls/syscall.tbl",
    },
    ARCHITECTURE.x86: {
        32: "arch/x86/entry/syscalls/syscall_32.tbl",
        64: "arch/x86/entry/syscalls/syscall_64.tbl",
    },
    ARCHITECTURE.xtensa: {
        32: "arch/xtensa/kernel/syscalls/syscall.tbl",
    },
}

ARCH_ABIS = {
    ARCHITECTURE.alpha: {64: ("common",)},
    ARCHITECTURE.arc: {
        32: tuple(),
        64: tuple(),
    },
    # NOTE: OABI not supported.
    ARCHITECTURE.arm: {
        32: ("common",),
    },
    ARCHITECTURE.arm64: {
        64: tuple(),
    },
    ARCHITECTURE.csky: {
        32: tuple(),
    },
    ARCHITECTURE.h8300: {
        16: tuple(),
    },
    ARCHITECTURE.hexagon: {
        32: tuple(),
    },
    ARCHITECTURE.ia64: {
        64: ("common",),
    },
    ARCHITECTURE.m68k: {
        16: ("common",),
        32: ("common",),
    },
    ARCHITECTURE.microblaze: {
        32: ("common",),
        64: ("common",),
    },
    ARCHITECTURE.mips: {
        32: ("n32",),
        64: ("n64",),
    },
    ARCHITECTURE.nds32: {
        32: tuple(),
    },
    ARCHITECTURE.nios2: {
        32: tuple(),
    },
    ARCHITECTURE.openrisc: {
        32: tuple(),
        64: tuple(),
    },
    ARCHITECTURE.parisc: {
        32: ("common", "32"),
        64: ("common", "64"),
    },
    ARCHITECTURE.powerpc: {
        # SPU is a coprocessor on CELL ppc -- unused on modern systems.
        32: ("common", "32", "nospu"),
        64: ("common", "64", "nospu"),
    },
    ARCHITECTURE.riscv: {
        32: tuple(),
        64: tuple(),
    },
    ARCHITECTURE.s390: {
        32: ("common", "32"),
        64: ("common", "64"),
    },
    ARCHITECTURE.sparc: {
        32: ("common", "32"),
        64: ("common", "64"),
    },
    ARCHITECTURE.x86: {
        32: ("i386",),
        64: ("common", "64"),
    },
    ARCHITECTURE.xtensa: {
        32: ("common",),
    },
}


GENERIC_SYSCALL_IMPLEMENTATIONS = [
    "block/ioprio.c",
    "drivers/char/random.c",
    "drivers/pci/syscall.c",
    "fs/aio.c",
    "fs/d_path.c",
    "fs/eventfd.c",
    "fs/eventpoll.c",
    "fs/exec.c",
    "fs/fcntl.c",
    "fs/fhandle.c",
    "fs/file.c",
    "fs/filesystems.c",
    "fs/fsopen.c",
    "fs/ioctl.c",
    "fs/io_uring.c",
    "fs/locks.c",
    "fs/namei.c",
    "fs/namespace.c",
    "fs/notify/fanotify/fanotify_user.c",
    "fs/notify/inotify/inotify_user.c",
    "fs/open.c",
    "fs/pipe.c",
    "fs/quota/quota.c",
    "fs/readdir.c",
    "fs/read_write.c",
    "fs/select.c",
    "fs/signalfd.c",
    "fs/splice.c",
    "fs/stat.c",
    "fs/statfs.c",
    "fs/sync.c",
    "fs/timerfd.c",
    "fs/userfaultfd.c",
    "fs/utimes.c",
    "fs/xattr.c",
    "ipc/mqueue.c",
    "ipc/msg.c",
    "ipc/sem.c",
    "ipc/shm.c",
    "ipc/syscall.c",
    "kernel/acct.c",
    "kernel/bpf/syscall.c",
    "kernel/capability.c",
    "kernel/compat.c",
    "kernel/events/core.c",
    "kernel/exec_domain.c",
    "kernel/exit.c",
    "kernel/fork.c",
    "kernel/futex/syscalls.c",
    "kernel/groups.c",
    "kernel/kcmp.c",
    "kernel/kexec.c",
    "kernel/kexec_file.c",
    "kernel/module.c",
    "kernel/nsproxy.c",
    "kernel/pid.c",
    "kernel/printk/printk.c",
    "kernel/ptrace.c",
    "kernel/reboot.c",
    "kernel/rseq.c",
    "kernel/sched/core.c",
    "kernel/sched/membarrier.c",
    "kernel/seccomp.c",
    "kernel/signal.c",
    "kernel/sys.c",
    "kernel/time/hrtimer.c",
    "kernel/time/itimer.c",
    "kernel/time/posix-stubs.c",
    "kernel/time/posix-timers.c",
    "kernel/time/time.c",
    "kernel/uid16.c",
    "mm/fadvise.c",
    "mm/madvise.c",
    "mm/memfd.c",
    "mm/mempolicy.c",
    "mm/migrate.c",
    "mm/mincore.c",
    "mm/mlock.c",
    "mm/mmap.c",
    "mm/mprotect.c",
    "mm/mremap.c",
    "mm/msync.c",
    "mm/nommu.c",
    "mm/oom_kill.c",
    "mm/process_vm_access.c",
    "mm/readahead.c",
    "mm/secretmem.c",
    "mm/swapfile.c",
    "net/compat.c",
    "net/socket.c",
    "security/keys/compat.c",
    "security/keys/keyctl.c",
    "security/landlock/syscalls.c",
]

ARCH_SYSCALL_IMPLEMENTATIONS = {
    ARCHITECTURE.alpha: [
        "arch/alpha/kernel/osf_sys.c",
        "arch/alpha/kernel/pci.c",
        "arch/alpha/kernel/pci-noop.c",
        "arch/alpha/kernel/signal.c",
    ],
    ARCHITECTURE.arc: [
        "arch/arc/kernel/process.c",
        "arch/arc/kernel/signal.c",
        "arch/arc/mm/cache.c",
    ],
    ARCHITECTURE.arm: [],
    ARCHITECTURE.arm64: [
        "arch/arm64/kernel/signal32.c",
        "arch/arm64/kernel/signal.c",
        "arch/arm64/kernel/sys32.c",
        "arch/arm64/kernel/sys.c",
    ],
    ARCHITECTURE.csky: [
        "arch/csky/kernel/signal.c",
        "arch/csky/kernel/syscall.c",
        "arch/csky/mm/syscache.c",
    ],
    ARCHITECTURE.h8300: [],
    ARCHITECTURE.hexagon: [],
    ARCHITECTURE.ia64: [],
    ARCHITECTURE.m68k: [],
    ARCHITECTURE.microblaze: [
        "arch/microblaze/kernel/sys_microblaze.c",
    ],
    ARCHITECTURE.mips: [
        "arch/mips/kernel/linux32.c",
        "arch/mips/kernel/signal32.c",
        "arch/mips/kernel/signal.c",
        "arch/mips/kernel/syscall.c",
        "arch/mips/mm/cache.c",
    ],
    ARCHITECTURE.nds32: [
        "arch/nds32/kernel/sys_nds32.c",
    ],
    ARCHITECTURE.nios2: [],
    ARCHITECTURE.openrisc: [],
    ARCHITECTURE.parisc: [],
    ARCHITECTURE.powerpc: [
        "arch/powerpc/kernel/pci_32.c",
        "arch/powerpc/kernel/pci_64.c",
        "arch/powerpc/kernel/rtas.c",
        "arch/powerpc/kernel/signal_32.c",
        "arch/powerpc/kernel/signal_64.c",
        "arch/powerpc/kernel/syscalls.c",
        "arch/powerpc/mm/book3s64/subpage_prot.c",
        "arch/powerpc/platforms/cell/spu_syscalls.c",
    ],
    ARCHITECTURE.riscv: [
        "arch/riscv/kernel/signal.c",
        "arch/riscv/kernel/sys_riscv.c",
    ],
    ARCHITECTURE.s390: [
        "arch/s390/kernel/compat_linux.c",
        "arch/s390/kernel/compat_signal.c",
        "arch/s390/kernel/guarded_storage.c",
        "arch/s390/kernel/runtime_instr.c",
        "arch/s390/kernel/signal.c",
        "arch/s390/kernel/sthyi.c",
        "arch/s390/kernel/syscall.c",
        "arch/s390/pci/pci_mmio.c",
    ],
    ARCHITECTURE.sparc: [
        "arch/sparc/kernel/sys_sparc_32.c",
        "arch/sparc/kernel/sys_sparc32.c",
        "arch/sparc/kernel/sys_sparc_64.c",
    ],
    ARCHITECTURE.x86: [
        "arch/x86/entry/common.c",
        "arch/x86/ia32/ia32_signal.c",
        "arch/x86/kernel/ioport.c",
        "arch/x86/kernel/ldt.c",
        "arch/x86/kernel/process_32.c",
        "arch/x86/kernel/process_64.c",
        "arch/x86/kernel/signal.c",
        "arch/x86/kernel/sys_ia32.c",
        "arch/x86/kernel/sys_x86_64.c",
        "arch/x86/kernel/tls.c",
        "arch/x86/kernel/vm86_32.c",
        "arch/x86/um/ldt.c",
        "arch/x86/um/syscalls_32.c",
        "arch/x86/um/syscalls_64.c",
        "arch/x86/um/tls_32.c",
    ],
    ARCHITECTURE.xtensa: [],
}
