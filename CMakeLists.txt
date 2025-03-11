cmake_minimum_required(VERSION 3.24)
project(rbase64
        VERSION 0.1.0
        LANGUAGES C
        DESCRIPTION
        "base64 algorithm")

add_library(${PROJECT_NAME} rbase64.c rbase64.h)
target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)


# Test runner executable testing the static library
if (NOT ${CMAKE_SYSTEM_NAME} MATCHES Generic)
    add_executable(${PROJECT_NAME}_test test/test.c)
    if (NOT TARGET runit)
        include(FetchContent)
        FetchContent_Declare(
                runit
                GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/runit.git
                GIT_TAG main
        )
        FetchContent_MakeAvailable(runit)
    endif ()

    target_link_libraries(${PROJECT_NAME}_test rbase64 runit)
    enable_testing()
    add_test(NAME ${PROJECT_NAME}_test COMMAND ${PROJECT_NAME}_test)
endif ()


# clang-format
set(FILES_FOR_FORMATTING
        rbase64.c
        rbase64.h
        test/test.c
        test/test.h
)

find_program(clang_format NAMES clang-format)
if (NOT clang_format)
    message(STATUS "Could not locate clang-format")
else ()
    file(GLOB format_files ${FILES_FOR_FORMATTING})
    add_custom_target(${PROJECT_NAME}_format COMMAND ${clang_format} -i -fallback-style=none -style=file --verbose ${format_files})
endif ()


