cmake_minimum_required(VERSION 3.22.1)
project(xts_aes_native LANGUAGES C CXX)

# Source files. Upstream VeraCrypt AES (Brian Gladman) is vendored verbatim
# in Crypto/ — we swap the portable C block cipher; XTS framing stays in
# xts_aes_native.cpp.
set(NATIVE_SOURCES
    xts_aes_native.cpp
    Serpent.c
    Twofish.c
    Crypto/Aescrypt.c
    Crypto/Aeskey.c
    Crypto/Aestab.c
)

# Upstream ARMv8 hardware-AES helpers (vaeseq_u8 / vaesdq_u8). Currently
# unreferenced — we keep the inline NEON 4-block path inside
# xts_aes_native.cpp — but compiling the file keeps it byte-identical to
# upstream and ready for a single-call-site swap later.
if(ANDROID_ABI STREQUAL "arm64-v8a"
        OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    list(APPEND NATIVE_SOURCES Crypto/Aes_hw_armv8.c)
    # The upstream file uses vaeseq_u8 / vaesdq_u8 intrinsics that require
    # the ARMv8 'aes' feature; enable it just for this translation unit.
    set_source_files_properties(Crypto/Aes_hw_armv8.c
        PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crypto")
endif()

add_library(xts_aes_native SHARED ${NATIVE_SOURCES})

target_include_directories(xts_aes_native PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/Common
)

target_link_libraries(xts_aes_native
    $<$<PLATFORM_ID:Android>:android>
    $<$<PLATFORM_ID:Android>:log>
)

set_target_properties(xts_aes_native PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Deterministic build ID for reproducible builds (F-Droid verification)
target_link_options(xts_aes_native PRIVATE "-Wl,--build-id=none")

# Aggressive optimization for crypto hot paths.
# CRYPTOPP_DISABLE_ASM disables Twofish.c's x64 assembly stubs and stops
# upstream config.h from selecting any inline-ASM SSE/AVX paths — we want
# pure portable C on x86_64 and the dedicated NEON path on arm64.
target_compile_options(xts_aes_native PRIVATE
    -O3 -DNDEBUG
    -DCRYPTOPP_DISABLE_ASM
)
