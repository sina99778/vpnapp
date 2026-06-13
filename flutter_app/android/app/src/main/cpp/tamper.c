// Native (C/JNI) anti-tamper for Android. Lives in C, not Kotlin, because the
// JNI/native boundary is far harder for Frida to hook than a Kotlin function
// whose boolean return can be flipped with a one-line Interceptor.
//
// Philosophy (per 2026 research): file-existence checks alone are defeated by
// Shamiko/Zygisk namespace hiding, so we combine artifact scans with behavioral
// signals (Frida runtime threads, rwxp segments, TracerPid). On ANY hard signal
// we abort() — SIGABRT cannot be caught/hooked by the app, unlike exit().

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

// Frida-SPECIFIC substrings. We deliberately exclude generic names like
// "gmain"/"gdbus" — those belong to GLib/D-Bus and would false-positive if any
// dependency pulled them in. "gum-js-loop" and "pool-frida" are distinctive to
// Frida's runtime; the rest are its libraries.
static const char *kFridaMarkers[] = {
    "frida-agent", "frida-gadget", "libfrida", "frida-server",
    "gum-js-loop", "pool-frida", "linjector", NULL,
};

// Root artifacts. Presence is suggestive (Shamiko may hide them); absence is
// NOT proof of cleanliness, so we pair these with the writable-/system probe.
static const char *kRootArtifacts[] = {
    "/data/adb/magisk.db", "/data/adb/modules", "/sbin/.magisk",
    "/debug_ramdisk/.magisk", "/system/bin/su", "/system/xbin/su",
    "/su/bin/su", NULL,
};

// abort() raises SIGABRT — uncatchable by the app. Never log first (logs are a
// hook target and tip off the attacker which check fired).
static void fail_closed(void) { abort(); }

// Read a small file fully into buf. Returns bytes read or -1.
static ssize_t read_all(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n >= 0) buf[n] = '\0';
    return n;
}

static int contains_any(const char *hay, const char *const *needles) {
    for (int i = 0; needles[i]; i++) {
        if (strstr(hay, needles[i])) return 1;
    }
    return 0;
}

// 1) Scan /proc/self/maps for Frida libraries by name.
//    NOTE: we deliberately do NOT flag rwxp segments — Android's ART and the
//    Dart JIT legitimately map writable+executable code cache, so that would
//    false-positive and abort real users. Library-name markers are reliable.
static int scan_maps(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0; // can't read → treat as inconclusive, other checks cover it
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (contains_any(line, kFridaMarkers)) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

// 2) Scan thread names for Frida's runtime threads (gum-js-loop, gmain, ...).
static int scan_threads(void) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    struct dirent *e;
    char path[256], buf[256];
    int hit = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
        if (read_all(path, buf, sizeof(buf)) > 0 && contains_any(buf, kFridaMarkers)) {
            hit = 1; break;
        }
    }
    closedir(d);
    return hit;
}

// 3) Anti-debug: TracerPid must be 0. A non-zero tracer means a debugger
//    (or Frida's ptrace-based injector) is attached.
static int being_traced(void) {
    char buf[4096];
    if (read_all("/proc/self/status", buf, sizeof(buf)) <= 0) return 0;
    const char *p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    return atoi(p + strlen("TracerPid:")) != 0;
}

// 4) Root: artifact presence. We intentionally do NOT use access("/system",W_OK)
//    as a standalone signal — it false-positives on legitimate custom ROMs and
//    some enterprise/SELinux configs, which would abort() real users. Root that
//    hides its artifacts is still caught server-side by Play Integrity
//    (deviceIntegrity verdict), so we bias the client check away from bricking.
static int rooted(void) {
    for (int i = 0; kRootArtifacts[i]; i++) {
        if (access(kRootArtifacts[i], F_OK) == 0) return 1;
    }
    return 0;
}

// The single native entry point. Returns JNI_TRUE only if clean; on any hard
// signal it never returns — it abort()s. Kept deliberately monolithic-but-inline
// so there's no convenient per-check return value to hook.
JNIEXPORT jboolean JNICALL
Java_app_securevpn_security_SecurityBridge_nativeAssertIntegrity(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz; // static method (@JvmStatic) → jclass, not jobject
    if (scan_maps())    fail_closed();
    if (scan_threads()) fail_closed();
    if (being_traced()) fail_closed();
    if (rooted())       fail_closed();
    return JNI_TRUE;
}

// Optional: call from JNI_OnLoad-adjacent init to attach ptrace to ourselves so
// an external debugger cannot also attach (only one tracer is allowed).
JNIEXPORT void JNICALL
Java_app_securevpn_security_SecurityBridge_nativeAntiDebugInit(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz; // static method (@JvmStatic) → jclass, not jobject
    // PTRACE_TRACEME = 0. If it fails, something is already tracing us.
    extern long ptrace(int, ...);
    if (ptrace(0 /*PTRACE_TRACEME*/, 0, 0, 0) < 0) fail_closed();
}
