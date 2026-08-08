package io.github.rootect.signal

/** What kind of problem a signal reports. */
public enum class Category {
    /** Magisk, KernelSU, APatch. */
    ROOT,

    /** Frida, Xposed/LSPosed, Zygisk. */
    HOOK,

    /** The app was repackaged, resigned, or modified. */
    TAMPER,

    /** An emulator or VM. */
    EMULATOR,

    /** A debugger or tracer is attached. */
    DEBUG,

    /** Unlocked bootloader, permissive SELinux. */
    ENVIRONMENT,
}
