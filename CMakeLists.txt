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


include(FetchContent)
FetchContent_Declare(
        rlibhelper
        GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/rlibhelper.git
        GIT_TAG main
)
FetchContent_MakeAvailable(rlibhelper)
set(FILES_FOR_FORMATTING
        rbase64.c
        rbase64.h
        test/test.c
        test/test.h
)
include(${CMAKE_BINARY_DIR}/_deps/rlibhelper-src/format.cmake)
format_files(${PROJECT_NAME} SOURCES ${FILES_FOR_FORMATTING})











