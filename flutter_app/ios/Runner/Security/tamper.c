// Native (C) anti-tamper for iOS. In C, not Swift, because dlsym/dyld checks
// and the sysctl anti-debug probe are far harder for Frida/Substrate to hook
// than a Swift Bool. Hard signals abort() (SIGABRT, uncatchable), per 2026
// fail-closed guidance — not a return value an attacker can flip.

#include "tamper.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>

static void fail_closed(void) { abort(); } // SIGABRT — cannot be caught/hooked

// Injected dylibs from Frida / Substrate / Cydia tooling. Renamed gadgets still
// usually carry one of these substrings somewhere in the image path.
static int dyld_has_injected_image(void) {
    static const char *markers[] = {
        "FridaGadget", "frida", "cynject", "libcycript", "SubstrateLoader",
        "MobileSubstrate", "libhooker", "libsubstitute", "Substitute",
        "RevealServer", NULL,
    };
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        for (int m = 0; markers[m]; m++) {
            if (strstr(name, markers[m])) return 1;
        }
    }
    return 0;
}

// Jailbreak filesystem artifacts (covers Cydia, Sileo, Zebra, checkra1n,
// Dopamine/palera1n, apt, ssh, Substrate).
static int jailbreak_files(void) {
    static const char *paths[] = {
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/usr/sbin/sshd", "/bin/bash",
        "/etc/apt", "/private/var/lib/apt",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/lib/libcycript.dylib", "/var/jb", "/var/dopamine",
        "/var/checkra1n", NULL,
    };
    struct stat st;
    for (int i = 0; paths[i]; i++) {
        if (stat(paths[i], &st) == 0) return 1;
    }
    return 0;
}

// Sandbox-escape probe: a stock app cannot write outside its container.
static int can_write_outside_sandbox(void) {
    const char *probe = "/private/.secvpn_probe";
    int fd = open(probe, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        close(fd);
        unlink(probe);
        return 1; // succeeded ⇒ jailbroken
    }
    return 0;
}

// Code-injection env vars.
static int dyld_insert_env(void) {
    return getenv("DYLD_INSERT_LIBRARIES") != NULL;
}

// Debugger attached? sysctl P_TRACED flag.
static int being_debugged(void) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return 0;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

int secvpn_environment_is_tampered(void) {
    if (dyld_has_injected_image())  fail_closed();
    if (dyld_insert_env())          fail_closed();
    if (jailbreak_files())          fail_closed();
    if (can_write_outside_sandbox()) fail_closed();
    if (being_debugged())           fail_closed();
    return 0; // clean (hard signals already aborted)
}

// PT_DENY_ATTACH via dlsym so the symbol isn't statically visible. Prevents a
// debugger from attaching after launch. (Private API — gate to non-App-Store
// builds if you submit to the store; fine for enterprise/sideload.)
void secvpn_anti_debug(void) {
    typedef int (*ptrace_fn)(int, pid_t, void *, int);
    ptrace_fn pt = (ptrace_fn) dlsym(RTLD_DEFAULT, "ptrace");
    if (!pt) return;
    pt(31 /*PT_DENY_ATTACH*/, 0, NULL, 0);
}
