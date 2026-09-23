package io.github.rootect

/** A check that could not finish. This is uncertainty, not evidence of compromise. */
public enum class InconclusiveCheck {
    NATIVE_LIBRARY,
    MOUNT_SCAN,
    ROOT_PATH_SCAN,
    SELINUX_SCAN,
    PROCESS_MAPS_SCAN,
    PROCESS_THREADS_SCAN,
    TRACER_SCAN,
    CODE_INTEGRITY_SCAN,
    PACKAGE_QUERY,
    RUNTIME_CHECK,
    SETTINGS_READ,
    SIGNING_CHECK,
    INTEGRITY_CHECK,
    HARDWARE_ATTESTATION,
}
