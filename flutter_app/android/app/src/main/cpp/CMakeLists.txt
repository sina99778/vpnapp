cmake_minimum_required(VERSION 3.22.1)
project(securevpn_native C)

# Anti-tamper native lib. Built into libsecurity.so, loaded by SecurityBridge.
add_library(security SHARED tamper.c)

# Harden the binary: optimize (folds the inline checks), strip symbols in the
# release build via the gradle externalNativeBuild cmake args.
target_compile_options(security PRIVATE
    -O2
    -fvisibility=hidden
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2)

# No external deps; the checks use libc + syscalls only.
find_library(log-lib log)
target_link_libraries(security ${log-lib})
