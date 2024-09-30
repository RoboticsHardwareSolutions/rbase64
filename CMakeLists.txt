cmake_minimum_required(VERSION 3.9)
project(rbase64_test
        VERSION 0.1.0
        LANGUAGES C
        DESCRIPTION
        "base64 algorithm")

add_library(rbase64 rbase64.c rbase64.h)

add_executable(rbase64_test
        rbase64.c
        rbase64.h
        test/runit/src/runit.c
        test/test.c)

target_include_directories(rbase64
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_include_directories(rbase64_test PRIVATE ./ ./test/runit/src)


if (MSVC OR MSYS OR MINGW)
    target_compile_definitions(rbase64_test PUBLIC -DRBASE64_FOR_WINDOWS)
endif ()

if (APPLE)
    target_compile_definitions(rbase64_test PUBLIC -DRBASE64_FOR_APPLE)
endif ()

if (UNIX AND NOT APPLE)
    target_compile_definitions(rbase64_test PUBLIC -DRBASE64_FOR_UNIX)
endif ()

set(FILES_FOR_FORMATTING
        rbase64.c
        rbase64.h
        test/test.c
        )

# clang-format
find_program(clang_format NAMES clang-format)
if (NOT clang_format)
    message(STATUS "Could not locate clang-format")
else ()
    file(GLOB format_files ${FILES_FOR_FORMATTING})
    add_custom_target(rbase64_format COMMAND ${clang_format} -i -fallback-style=none -style=file --verbose ${format_files})
endif ()


enable_testing()
add_test(NAME rbase64_test COMMAND rbase64_test)
