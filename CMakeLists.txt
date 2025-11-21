

cmake_minimum_required(VERSION 3.10)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
project(arnika)

include(cmake/golang.cmake)
include(cmake/flags.cmake)

execute_process(
    COMMAND git describe --tags --always
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)


# compose ldflags as a single string and pass as a separate COMMAND arg
set(GO_LDFLAGS "-w -s -extldflags=-Wl,-Bsymbolic -X main.Version=${VERSION} -X main.APPName=${PROJECT_NAME}")

# set CMAKE_GO_FLAGS as a list so golang.cmake expands into: -trimpath -ldflags "<GO_LDFLAGS>"
set(CMAKE_GO_FLAGS -trimpath -ldflags "${GO_LDFLAGS}")

add_go_executable(arnika main.go)