#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>

typedef int (*ioctl_func_t)(int fd, unsigned long request, ...);

// Helper function to write to our own log
void log_msg(const char *format, ...) {
    FILE *f = fopen("/tmp/kvm_hook.log", "a");
    if (f) {
        va_list args;
        va_start(args, format);
        vfprintf(f, format, args);
        va_end(args);
        fclose(f);
    }
}

int ioctl(int fd, unsigned long request, ...) {
    static ioctl_func_t real_ioctl = NULL;
    if (!real_ioctl) {
        real_ioctl = (ioctl_func_t)dlsym(RTLD_NEXT, "ioctl");
    }

    va_list args;
    va_start(args, request);
    void *argp = va_arg(args, void *);
    va_end(args);

    if (request == KVM_SET_CPUID2) {
        log_msg("[+] Intercepted KVM_SET_CPUID2!\n");
        struct kvm_cpuid2 *cpuid = (struct kvm_cpuid2 *)argp;
        for (int i = 0; i < cpuid->nent; i++) {
            if (cpuid->entries[i].function == 1) {
                log_msg("    [-] Clearing Hypervisor Bit.\n");
                cpuid->entries[i].ecx &= ~(1 << 31);
            }
        }
    }

    return real_ioctl(fd, request, argp);
}
