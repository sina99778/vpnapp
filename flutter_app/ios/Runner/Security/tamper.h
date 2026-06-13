#ifndef SECUREVPN_TAMPER_H
#define SECUREVPN_TAMPER_H

// Returns 1 if the environment looks compromised (jailbreak / injected
// dylib / debugger). For HARD signals the implementation abort()s and never
// returns. Add to Runner's bridging header so Swift can call it.
int secvpn_environment_is_tampered(void);

// Apply PT_DENY_ATTACH so a debugger cannot attach. Call once, very early.
void secvpn_anti_debug(void);

#endif
