// Copyright (c) 2024 Nadav Amit
//
// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <sys/vfs.h>
#include <dlfcn.h>
#include <sched.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/membarrier.h>

#define PAGE_SIZE 4096
#define HUGE_PAGE_SIZE (2 * 1024 * 1024) // 2MB
#define PAGES_PER_HUGE_PAGE (HUGE_PAGE_SIZE / PAGE_SIZE)

#define AFS_SUPER_MAGIC      0x5346414F  // 'OFAS' (AFS)
#define BCACHEFS_SUPER_MAGIC 0x42465331  // 'BFS1' (BCacheFS)
#define EROFS_SUPER_MAGIC    0xE0F5E1E2  // EROFS
#define NFS_SUPER_MAGIC      0x6969      // NFS
#define SMB_SUPER_MAGIC      0xFE534D42  // 'BMSF' (SMB/CIFS)
#define ZONEFS_SUPER_MAGIC   0x5A4F4653  // 'SFOZ' (ZoneFS)
#define XFS_SUPER_MAGIC      0x58465342  // 'BFS1' (XFS)

#define MAX_EVICTION_TRIES 3

#define array_size(arr) (sizeof(arr) / sizeof(arr[0]))

// Function pointer types for the syscalls we'll hook
typedef pid_t (*fork_t)(void);
typedef int (*clone_t)(int (*fn)(void *), void *stack, int flags, void *arg, ...);
typedef void* (*dlopen_t)(const char *filename, int flags);

static fork_t original_fork;
static clone_t original_clone;
static dlopen_t original_dlopen;
static int verbose = -1;

#define pr_debug(...) do { if (verbose >= 2) fprintf(stderr, __VA_ARGS__); } while (0)
#define pr_info(...) do { if (verbose >= 1) fprintf(stderr, __VA_ARGS__); } while (0)
#define pr_warn(...) do { if (verbose >= 0) fprintf(stderr, __VA_ARGS__); } while (0)

// If we want to reload libc, it would be necessary not to use it in between
#ifdef __x86_64__
static long direct_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile(
        "syscall"
        : "=a" (ret)
        : "a" (nr),    /* syscall number in rax */
          "D" (a1),    /* arg1 in rdi */
          "S" (a2),    /* arg2 in rsi */
          "d" (a3),    /* arg3 in rdx */
          "r" (r10),   /* arg4 in r10 */
          "r" (r8),    /* arg5 in r8 */
          "r" (r9)     /* arg6 in r9 */
        : "rcx", "r11", "memory"
    );
    return ret;
}

#else
#error "Architecture not supported"
#endif

static long direct_fadvise64(int fd, off_t offset, off_t len, int advice) {
    return direct_syscall(SYS_fadvise64, fd, offset, len, advice, 0, 0);
}

static long direct_madvise(void *addr, size_t length, int advice) {
    return direct_syscall(SYS_madvise, (long)addr, length, advice, 0, 0, 0);
}

static void *direct_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return (void *)direct_syscall(SYS_mmap, (long)addr, length, prot, flags, fd, offset);
}

static int direct_flock(int fd, int operation) {
    return direct_syscall(__NR_flock, fd, operation, 0, 0, 0, 0);
}

static int direct_open(const char *pathname, int flags, mode_t mode) {
    return direct_syscall(__NR_openat, AT_FDCWD, (long)pathname, flags, mode, 0, 0);
}

static int direct_close(int fd) {
    return direct_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
}

static int direct_getpid(void) {
    return direct_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
}

static int direct_fsync(int fd) {
    return direct_syscall(__NR_fsync, fd, 0, 0, 0, 0, 0);
}

static int direct_cachestat(unsigned int fd, 
                          struct cachestat_range *cstat_range,
                          struct cachestat *cstat,
                          unsigned int flags) {
    return direct_syscall(__NR_cachestat, fd, (long)cstat_range, (long)cstat,
                          flags, 0, 0);
}

static int ptr_to_err(void *ptr) {
    long ptr_val = (long)(uintptr_t)ptr;
    return (ptr_val < 0) ? ptr_val : 0;
}

static void fault_in_address(void *addr) {
    volatile unsigned char *ptr = (unsigned char *)addr;
    volatile unsigned char dummy;
    dummy = *ptr;
    (void)dummy;
}

static void fault_in_range(void *addr, size_t length) {
    for (size_t offset = 0; offset < length; offset += PAGE_SIZE) {
        fault_in_address((void *)(addr + offset));
    }
}

static unsigned long round_down(unsigned long value, unsigned long alignment) {
    if (alignment == 0) {
        return value;
    }
    return (value / alignment) * alignment;
}

static unsigned long round_up(unsigned long value, unsigned long alignment) {
    if (alignment == 0) {
        return value;
    }
    return ((value + alignment - 1) / alignment) * alignment;
}

bool is_fs_support_huge_folios(const char *path) {
    struct statfs fs_info;
    // Retrieve filesystem information
    if (statfs(path, &fs_info) != 0) {
        perror("statfs failed");
        return false;
    }
    
    // Check if the filesystem type matches those that support huge folios
    switch (fs_info.f_type) {
        case AFS_SUPER_MAGIC:      // AFS
        case BCACHEFS_SUPER_MAGIC: // BCacheFS
        case EROFS_SUPER_MAGIC:    // EROFS
        case NFS_SUPER_MAGIC:      // NFS
        case SMB_SUPER_MAGIC:      // SMB (CIFS)
        case ZONEFS_SUPER_MAGIC:   // ZoneFS
        case XFS_SUPER_MAGIC:      // XFS
            return true;
        default:
            return false;
    }
}

static ssize_t get_file_pmd_mapped(const char *target_path, unsigned long target_start) {
    FILE *maps;
    char line[1024];
    unsigned long start, end;
    char permissions[5];
    char path[1024];
    int offset;
    char dev[32];
    unsigned long inode;
    bool found = false;
    unsigned long file_pmd_mapped = 0;
    
    maps = fopen("/proc/self/smaps", "r");
    if (!maps) {
        pr_debug("Failed to open /proc/self/smaps\n");
        return -1;
    }

    while (fgets(line, sizeof(line), maps)) {
        // Reset found_target when we hit a new mapping
        if (sscanf(line, "%lx-%lx %4s %x %s %lu %s", &start, &end, 
                   permissions, &offset, dev, &inode, path) >= 6) {
            
            // Check if this is our target entry
            found = (start == target_start && strcmp(path, target_path) == 0);
        }
        
        // If we found our target entry, look for FilePmdMapped
        if (found && strncmp(line, "FilePmdMapped:", 14) == 0) {
            sscanf(line, "FilePmdMapped: %lu", &file_pmd_mapped);
            fclose(maps);
            return file_pmd_mapped * 1024;
        }
    }
    
    fclose(maps);
    return -1;  // Entry not found
}

static void print_promotion_results(int pid, const char *path, unsigned long offset,
                                    unsigned long start, size_t aligned_length,
                                    unsigned long end) {
    if (verbose < 1) {
        return;
    }

    ssize_t mapped = get_file_pmd_mapped(path, start);
    if (mapped >= 0) {
        unsigned long unaligned_delta = end - start - aligned_length;

        if ((size_t)mapped == aligned_length && unaligned_delta == 0) {
            pr_debug("[%d] [%s:0x%lx] mapped 0x%lx\n", pid, path, offset, mapped);
        } else {
            pr_info("[%d] [%s:0x%lx] mapped 0x%lx / 0x%lx\n", pid, path, offset, mapped, aligned_length);
            if (unaligned_delta != 0) {
                pr_debug("[%d] [%s:0x%lx] unaligned 0x%lx\n", pid, path, offset, unaligned_delta);
            }
        }
    } else {
        pr_info("[%d] [%s:0x%lx] Error checking mapped pages\n", pid, path, offset);
    }
}

void sleep_microseconds(int microseconds) {
    struct timespec req;

    // Convert microseconds to seconds and nanoseconds for nanosleep
    req.tv_sec = microseconds / 1000000;
    req.tv_nsec = (microseconds % 1000000) * 1000;

    // Perform the sleep
    if (nanosleep(&req, NULL) == -1) {
        perror("nanosleep failed");
    }
}

typedef enum {
    CACHING_STAT_FULLY_CACHED = 0,
    CACHING_STAT_PARTIALLY_CACHED = 1,
    CACHING_STAT_NOT_CACHED = 2,
    CACHING_STAT_UNKNOWN = 3,
} caching_stat_t;

static caching_stat_t get_cache_stat(int pid, int fd, const char *path, uint64_t offset, uint64_t length) {
    struct cachestat_range cstat_range = {
        .off = offset,
        .len = length
    };
    struct cachestat cstat = {0};

    int err = direct_cachestat(fd, &cstat_range, &cstat, 0);
    if (err < 0) {
        pr_warn("[%d] [%s:0x%lx] Cachestat failed: %s\n", pid, path, offset, strerror(-err));
        // It might just be unsupported, so we'll continue
        return CACHING_STAT_UNKNOWN;
    }

    pr_debug("[%d] [%s:0x%lx] Cache status: cached=%llu dirty=%llu writeback=%llu evicted=%llu recent_evicted=%llu\n",
                pid, path, offset, cstat.nr_cache, cstat.nr_dirty, cstat.nr_writeback,
                cstat.nr_evicted, cstat.nr_recently_evicted);

    // No need for eviction if no pages or all pages are in cache
    if (cstat.nr_cache == length / PAGE_SIZE) {
        return CACHING_STAT_FULLY_CACHED;
    }

    return cstat.nr_cache == 0 ? CACHING_STAT_NOT_CACHED : CACHING_STAT_PARTIALLY_CACHED;
}

static int permissions_to_prot(const char *permissions) {
    int prot = PROT_NONE;
    if (permissions[0] == 'r') prot |= PROT_READ;
    if (permissions[1] == 'w') prot |= PROT_WRITE;
    if (permissions[2] == 'x') prot |= PROT_EXEC;
    return prot;
}

static void parse_debug_level(void) {
    const char *debug_env = getenv("HUGEPAGE_PROMOTE_DEBUG");
    if (!debug_env) {
        return;
    }

    int debug_level = atoi(debug_env);
    if (debug_level >= 0 && debug_level <= 2) {
        verbose = debug_level;
    }
}

static bool try_fast_fault_in(int pid, int fd, const char *path, unsigned long offset,
                             unsigned long aligned_start, size_t aligned_length) {
    int err;
    void *mapping_minor = direct_mmap((void *)aligned_start, aligned_length,
                                    PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE,
                                    fd, offset);

    if ((err = ptr_to_err(mapping_minor)) < 0) {
        pr_warn("[%d] [%s:0x%lx] Remapping failed: %s\n", pid, path, offset, strerror(-err));
        return false;
    }

    if ((err = direct_madvise((void *)aligned_start, aligned_length, MADV_HUGEPAGE)) < 0) {
        pr_warn("[%d] [%s:0x%lx] MADV_HUGEPAGE failed: %s\n", pid, path, offset, strerror(-err));
        return false;
    }

    fault_in_range((void *)aligned_start, aligned_length);

    // Check if all pages are faulted in
    ssize_t mapped = get_file_pmd_mapped(path, aligned_start);
    
    return mapped >= 0 && (size_t)mapped == aligned_length;
}

// Evict pages from cache and check if they are evicted
// Returns 1 if pages are evicted, 0 if they are not, and -1 on error
static int try_evict(int pid, int fd, const char *path, unsigned long offset,
                     size_t length) {
    int err;

    if ((err = direct_fadvise64(fd, offset, length, POSIX_FADV_DONTNEED)) < 0) {
        pr_warn("[%d] [%s:0x%lx] FADV_DONTNEED failed: %s\n", pid, path, offset, strerror(-err));
        return -EFAULT;
    }

    if ((err = direct_fsync(fd)) < 0) {
        pr_warn("[%d] [%s:0x%lx] fsync failed: %s\n", pid, path, offset, strerror(-err));
        return -EFAULT;
    }

    caching_stat_t stat = get_cache_stat(pid, fd, path, offset, length);

    switch (stat) {
        case CACHING_STAT_FULLY_CACHED:
        case CACHING_STAT_PARTIALLY_CACHED:
            return -EAGAIN;
        case CACHING_STAT_NOT_CACHED:
            return 0;
        default:
            return -EFAULT;
    }
}

static void promote_to_huge_pages(void) {
    int err;
    FILE *maps;
    char line[1024];
    unsigned long start, end, offset, inode;
    char permissions[5];
    char path[1024];
    char dev[32];

    parse_debug_level();

    int pid = direct_getpid();

    maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        pr_debug("[%d] Failed to open /proc/self/maps: %s\n", pid, strerror(errno));
        return;
    }

    while (fgets(line, sizeof(line), maps)) {
        path[0] = '\0';
        if (sscanf(line, "%lx-%lx %4s %lx %s %lu %s", &start, &end, 
                   permissions, &offset, dev, &inode, path) < 6) {
            continue;
        }

        if (path[0] == '\0' || path[0] == '[') {
            continue;
        }

        int prot = permissions_to_prot(permissions);

        // Only process executable file-backed segments
        if (prot != (PROT_READ | PROT_EXEC) || inode == 0) {
            pr_debug("[%d] [%s:0x%lx] Skipping non-readable/executable region\n", pid, path, offset);
            continue;
        }

        pr_debug("[%d] [%s:0x%lx] Processing executable segment at %lx-%lx from %s\n", 
                    pid, path, offset, start, end, path[0] ? path : "unknown");
        
        unsigned long aligned_start = round_up(start, HUGE_PAGE_SIZE);
        unsigned long aligned_end = round_down(end, HUGE_PAGE_SIZE);
        
        if (aligned_start >= aligned_end) {
            continue;
        }

        if (!is_fs_support_huge_folios(path)) {
            pr_info("[%d] [%s:0x%lx] Skipping non-hugepage filesystem\n", pid, path, offset);
            continue;
        }

        size_t aligned_length = aligned_end - aligned_start;
        off_t aligned_offset = offset + (aligned_start - start);
        
        // Open file and acquire lock
        int fd = direct_open(path, O_RDONLY, 0);
        if (fd == -1) {
            pr_debug("[%d] [%s:0x%lx] Failed to open file: %s\n", pid, path, offset, strerror(errno));
            continue;
        }

        if ((err = direct_flock(fd, LOCK_EX)) < 0) {
            pr_warn("[%d] [%s:0x%lx] Failed to acquire lock: %s\n", pid, path, offset, strerror(-err));
            direct_close(fd);
            continue;
        }

        caching_stat_t cache_stat = get_cache_stat(pid, fd, path, aligned_offset, aligned_length);
        if (cache_stat == CACHING_STAT_FULLY_CACHED &&
            try_fast_fault_in(pid, fd, path, offset, aligned_start, aligned_length)) {
            pr_debug("[%d] [%s:0x%lx] Pages are faulted in using minor fault\n", pid, path, offset);
            goto do_next;
        }

        void *new_mapping = direct_mmap((void *)aligned_start, aligned_length, prot,
                                        MAP_FIXED | MAP_PRIVATE, fd, aligned_offset);
        
        if ((err = ptr_to_err(new_mapping)) < 0) {
            pr_warn("[%d] [%s:0x%lx] Remapping failed: %s\n", pid, path, offset, strerror(-err));
            goto do_next;
        }

        if ((err = direct_madvise(new_mapping, aligned_length, MADV_HUGEPAGE)) < 0) {
            pr_warn("[%d] [%s:0x%lx] MADV_HUGEPAGE failed: %s\n", pid, path, offset, strerror(-err));
            goto do_next;
        }

        if (cache_stat != CACHING_STAT_NOT_CACHED) {
            for (int i = 0; i < MAX_EVICTION_TRIES; i++) {
                int err = try_evict(pid, fd, path, aligned_offset, aligned_length);

                if (err == 0) {
                    pr_debug("[%d] [%s:0x%lx] Pages are evicted\n", pid, path, offset);
                    break;
                } else if (err == -EAGAIN) {
                    pr_debug("[%d] [%s:0x%lx] Eviction did not complete... waiting\n", pid, path, offset);
                    sleep_microseconds(100);
                } else {
                    pr_warn("[%d] [%s:0x%lx] Eviction failed: %s\n", pid, path, offset, strerror(-err));
                    goto do_next;
                }
            }
        }
    
        pr_debug("[%d] [%s:0x%lx] Touching pages from %p (length=0x%lx)\n", pid, path, offset, new_mapping, aligned_length);
        fault_in_range(new_mapping, aligned_length);
        print_promotion_results(pid, path, offset, start, aligned_length, end);
        
do_next:
        // Release lock and close file
        direct_flock(fd, LOCK_UN);
        direct_close(fd);
    }
    fclose(maps);
}

// Hook implementations for fork and clone remain the same
pid_t fork(void) {
    pid_t pid;
    
    if (!original_fork) {
        original_fork = dlsym(RTLD_NEXT, "fork");
        if (!original_fork) {
            pr_debug("Failed to get original fork: %s\n", dlerror());
            return -1;
        }
    }
    
    pid = original_fork();
    if (pid == 0) {
        // Child process
        promote_to_huge_pages();
    }
    return pid;
}

int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
    if (!original_clone) {
        original_clone = dlsym(RTLD_NEXT, "clone");
        if (!original_clone) {
            pr_debug("Failed to get original clone: %s\n", dlerror());
            return -1;
        }
    }
    
    // If CLONE_VM is not set, this is like fork and we need to handle it
    if (!(flags & CLONE_VM)) {
        int result = original_clone(fn, stack, flags, arg);
        if (result == 0) {
            // Child process
            promote_to_huge_pages();
        }
        return result;
    }
    
    // Otherwise, just pass through to original clone
    return original_clone(fn, stack, flags, arg);
}

// New dlopen hook implementation
void* dlopen(const char *filename, int flags) {
    void *handle;
    
    if (!original_dlopen) {
        original_dlopen = dlsym(RTLD_NEXT, "dlopen");
        if (!original_dlopen) {
            pr_debug("Failed to get original dlopen: %s\n", dlerror());
            return NULL;
        }
    }
    
    // First call the original dlopen
    handle = original_dlopen(filename, flags);
    
    if (handle) {
        pr_debug("Successfully loaded library: %s\n", filename ? filename : "NULL");
        // Promote the newly loaded library to huge pages
        promote_to_huge_pages();
    } else {
        pr_debug("Failed to load library: %s (%s)\n", 
                   filename ? filename : "NULL", dlerror());
    }
    
    return handle;
}

// Constructor to handle initial process
void __attribute__((constructor)) init(void) {
    promote_to_huge_pages();
}