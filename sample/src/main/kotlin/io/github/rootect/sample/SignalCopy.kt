package io.github.rootect.sample

import io.github.rootect.SignalId

// Plain-English descriptions of what each signal means.
//
// These live in the sample rather than the library on purpose: Rootect reports evidence and
// ships no user-facing text, so wording and localisation stay the host app's business.
internal object SignalCopy {

    /** One-line explanation of a signal, or a fallback if the catalogue grows. */
    fun of(id: SignalId): String = when (id) {
        SignalId.SU_BINARY ->
            "An su or busybox binary is present on a system path."
        SignalId.MAGISK_ARTIFACT ->
            "Magisk, KernelSU or APatch is visible in this process's mount table."
        SignalId.ROOT_MANAGER_PACKAGE ->
            "A root manager app is installed."
        SignalId.SYSTEM_PARTITION_WRITABLE ->
            "A partition that ships read-only is mounted writable."
        SignalId.KERNEL_ROOT_SYSCALL ->
            "The kernel answered a root framework's private syscall."

        SignalId.TEST_KEYS_BUILD ->
            "The OS was signed with test keys rather than a vendor release key."
        SignalId.SELINUX_PERMISSIVE ->
            "SELinux is not enforcing."
        SignalId.BOOTLOADER_UNLOCKED ->
            "Verified Boot reports the bootloader is unlocked."
        SignalId.ATTESTATION_BOOT_UNVERIFIED ->
            "The device's secure hardware reports the bootloader unlocked or boot unverified."
        SignalId.ATTESTATION_SOFTWARE_ONLY ->
            "No hardware-backed attestation — the answer came from software and is weaker."
        SignalId.ATTESTATION_CONTRADICTS_PROPERTIES ->
            "System properties claim a locked device; the secure hardware says otherwise."

        SignalId.FRIDA_LIBRARY_MAPPED ->
            "A Frida agent is mapped into this process."
        SignalId.FRIDA_THREAD_PRESENT ->
            "Threads belonging to Frida are running inside this process."
        SignalId.XPOSED_FRAMEWORK_PRESENT ->
            "Xposed or LSPosed is loaded."
        SignalId.CODE_SECTION_MODIFIED ->
            "Our own machine code no longer matches the file it came from — an inline hook."
        SignalId.DETECTOR_TAMPERED ->
            "The native layer loaded but answered wrongly — something replaced it."

        SignalId.DEBUGGER_ATTACHED ->
            "A debugger is attached."
        SignalId.TRACER_ATTACHED ->
            "Another process is tracing this one."

        SignalId.SIGNATURE_MISMATCH ->
            "This APK is signed with a different certificate than expected — repackaged."
        SignalId.DEBUGGABLE_BUILD ->
            "The app is marked debuggable."
        SignalId.UNTRUSTED_INSTALLER ->
            "The app was not installed from a trusted store."

        SignalId.EMULATOR_FINGERPRINT ->
            "This is an emulator or virtual machine."
    }
}
