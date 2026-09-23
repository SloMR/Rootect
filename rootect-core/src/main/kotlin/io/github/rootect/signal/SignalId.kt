package io.github.rootect.signal

/** The catalogue of things Rootect can find. */
public enum class SignalId(
    public val category: Category,
    public val confidence: Confidence,
) {

    // ── Root artefacts ────────────────────────────────────────────────────────
    SU_BINARY(Category.ROOT, Confidence.STRONG),
    MAGISK_ARTIFACT(Category.ROOT, Confidence.STRONG),
    ROOT_MANAGER_PACKAGE(Category.ROOT, Confidence.MODERATE),
    SYSTEM_PARTITION_WRITABLE(Category.ROOT, Confidence.STRONG),

    /** prctl(0xDEADBEEF) returned data. A stock kernel rejects it with EINVAL. */
    KERNEL_ROOT_SYSCALL(Category.ROOT, Confidence.CONCLUSIVE),

    // ── OS posture ────────────────────────────────────────────────────────────
    TEST_KEYS_BUILD(Category.ENVIRONMENT, Confidence.WEAK),
    SELINUX_PERMISSIVE(Category.ENVIRONMENT, Confidence.STRONG),
    BOOTLOADER_UNLOCKED(Category.ENVIRONMENT, Confidence.STRONG),

    /** The Developer options toggle is on. Common on honest devices, so posture not proof. */
    DEVELOPER_OPTIONS_ENABLED(Category.ENVIRONMENT, Confidence.WEAK),

    /** USB debugging is enabled; this does not mean a computer is authorized. */
    ADB_ENABLED(Category.ENVIRONMENT, Confidence.WEAK),

    /** Samsung reports its persistent Knox warranty fuse as tripped. */
    KNOX_WARRANTY_BIT_TRIPPED(Category.ENVIRONMENT, Confidence.STRONG),

    /** Secure hardware reports the bootloader unlocked or boot unverified. */
    ATTESTATION_BOOT_UNVERIFIED(Category.ENVIRONMENT, Confidence.STRONG),

    /** No TEE-backed attestation available, so the answer came from software. */
    ATTESTATION_SOFTWARE_ONLY(Category.ENVIRONMENT, Confidence.MODERATE),

    /** The properties claim a locked, verified device; the hardware disagrees. */
    ATTESTATION_CONTRADICTS_PROPERTIES(Category.ENVIRONMENT, Confidence.CONCLUSIVE),

    // ── Instrumentation ───────────────────────────────────────────────────────
    FRIDA_LIBRARY_MAPPED(Category.HOOK, Confidence.STRONG),
    FRIDA_THREAD_PRESENT(Category.HOOK, Confidence.STRONG),
    XPOSED_FRAMEWORK_PRESENT(Category.HOOK, Confidence.STRONG),

    /** Our machine code in memory no longer matches the .so on disk. */
    CODE_SECTION_MODIFIED(Category.HOOK, Confidence.CONCLUSIVE),

    /** The native layer loaded but failed or returned an invalid result. */
    DETECTOR_TAMPERED(Category.HOOK, Confidence.STRONG),

    // ── Debuggers ─────────────────────────────────────────────────────────────
    DEBUGGER_ATTACHED(Category.DEBUG, Confidence.MODERATE),
    TRACER_ATTACHED(Category.DEBUG, Confidence.STRONG),

    // ── App integrity ─────────────────────────────────────────────────────────
    SIGNATURE_MISMATCH(Category.TAMPER, Confidence.CONCLUSIVE),
    DEBUGGABLE_BUILD(Category.TAMPER, Confidence.MODERATE),
    UNTRUSTED_INSTALLER(Category.TAMPER, Confidence.WEAK),

    // ── Emulation ─────────────────────────────────────────────────────────────
    EMULATOR_FINGERPRINT(Category.EMULATOR, Confidence.STRONG),
}
