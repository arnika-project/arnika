set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

cmake_minimum_required(VERSION 3.10)

execute_process(
    COMMAND git describe --tags --always
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

project(arnika Go)

set(CMAKE_PROJECT_VERSION ${VERSION})

include(cmake/golang.cmake)
include(cmake/flags.cmake)

set(ENV{CGO_ENABLED} "0")

# compose ldflags as a single string and pass as a separate COMMAND arg
set(GO_LDFLAGS "-w -s -extldflags=-Wl,-Bsymbolic -X main.Version=${VERSION} -X main.APPName=${PROJECT_NAME}")

# set CMAKE_GO_FLAGS as a list so golang.cmake expands into: -trimpath -ldflags "<GO_LDFLAGS>"
set(CMAKE_GO_FLAGS -trimpath -ldflags "${GO_LDFLAGS}")

# Setup and install arnika application.
add_go_executable(arnika main.go)

# Configure the service file so that it knows where the
# binary was installed.
set(SERVICE_NAME arnika.service)
set(EXE_PATH ${CMAKE_INSTALL_PREFIX}/bin/arnika)
set(SERVICE_IN ${SERVICE_NAME}.in)
set(SERVICE_OUT ${CMAKE_CURRENT_BINARY_DIR}/${SERVICE_NAME})
configure_file(${SERVICE_IN} ${SERVICE_OUT} @ONLY)

# Install the service file in the share directory. The post
# install RPM script will handle placing the file where
# it's supposed to go.
install(FILES ${SERVICE_OUT} DESTINATION share)

# Configure the scripts that are executed by the RPM.
# This could be done without going through the rigmarole of
# using configures, but I don't want to hard-code the name
# of the service into each file.
#
# Each script has the option of performing verbose logging
# Switch this variable to TRUE to enable those logs.
# I found this helpful while troubleshooting package upgrades.
set(VERBOSE_LOGGING FALSE)
set(POST_IN ${CMAKE_CURRENT_LIST_DIR}/post.sh.in)
set(POST_OUT ${CMAKE_CURRENT_BINARY_DIR}/post.sh)
configure_file(${POST_IN} ${POST_OUT} @ONLY)
set(POSTUN_IN ${CMAKE_CURRENT_LIST_DIR}/postun.sh.in)
set(POSTUN_OUT ${CMAKE_CURRENT_BINARY_DIR}/postun.sh)
configure_file(${POSTUN_IN} ${POSTUN_OUT} @ONLY)
set(PREUN_IN ${CMAKE_CURRENT_LIST_DIR}/preun.sh.in)
set(PREUN_OUT ${CMAKE_CURRENT_BINARY_DIR}/preun.sh)
configure_file(${PREUN_IN} ${PREUN_OUT} @ONLY)


set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${POST_OUT})
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE ${POSTUN_OUT})
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE ${PREUN_OUT})
set(CPACK_RPM_PACKAGE_REQUIRES_POSTUN "systemd")
set(CPACK_RPM_PACKAGE_REQUIRES_PREUN "systemd")
set(CPACK_RPM_PACKAGE_REQUIRES_POST "systemd")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
include(CPack)