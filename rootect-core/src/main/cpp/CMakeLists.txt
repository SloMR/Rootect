cmake_minimum_required(VERSION 3.22.1)

project(rootect LANGUAGES CXX)

add_library(rootect SHARED
        rootect.cpp
        detect_root.cpp
)

target_compile_features(rootect PRIVATE cxx_std_17)

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

        # 16 KB page alignment. NDK 28 defaults to this, but a misaligned.
        -Wl,-z,max-page-size=16384

        # Do not re-export symbols from any static library we link.
        -Wl,--exclude-libs,ALL
)
