cmake_minimum_required(VERSION 3.22.1)

project(rootect LANGUAGES CXX)

# A distribution can supply a different value without editing the sources. Zero preserves
# the shared upstream build; it is a compatibility default, not a secret.
set(ROOTECT_OBFUSCATION_SEED "0x00000000" CACHE STRING
        "32-bit hexadecimal seed used to diversify Rootect's hidden native strings")
string(LENGTH "${ROOTECT_OBFUSCATION_SEED}" ROOTECT_OBFUSCATION_SEED_LENGTH)
if (NOT ROOTECT_OBFUSCATION_SEED_LENGTH EQUAL 10 OR
        NOT ROOTECT_OBFUSCATION_SEED MATCHES "^0[xX][0-9A-Fa-f]+$")
    message(FATAL_ERROR
            "ROOTECT_OBFUSCATION_SEED must be exactly eight hexadecimal digits (0x00000000..0xFFFFFFFF)")
endif()

add_library(rootect SHARED
        rootect.cpp
        detect/detect_root.cpp
        detect/detect_hooks.cpp
        detect/detect_emulator.cpp
)

# So "core/..." and "detect/..." resolve the same from every source file.
target_include_directories(rootect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(rootect PRIVATE cxx_std_17)

target_compile_definitions(rootect PRIVATE
        ROOTECT_OBFUSCATION_SEED=${ROOTECT_OBFUSCATION_SEED}u
)

target_compile_options(rootect PRIVATE
        # Only the JNI entry points carry JNIEXPORT (visibility("default")).
        -fvisibility=hidden
        -fvisibility-inlines-hidden

        -fno-exceptions
        -fno-rtti

        -ffunction-sections
        -fdata-sections
)

target_link_options(rootect PRIVATE
        -Wl,--gc-sections

        # 16 KB page alignment. Pinned, not inherited: a misaligned .so will not load at all
        # on a 16 KB-page device.
        -Wl,-z,max-page-size=16384

        # Do not re-export symbols from any static library we link.
        -Wl,--exclude-libs,ALL
)
