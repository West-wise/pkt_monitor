cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_BUILD_TYPE Debug)

# set jemlloc path
link_directories(/usr/lib/x86_64-linux-gnu)

# set project name
project(project1_psh LANGUAGES C)

# set header files path
include_directories(${CMAKE_SOURCE_DIR}/header)

# set source var
set(SOURCES
    ${CMAKE_SOURCE_DIR}/src/log_db.c
	${CMAKE_SOURCE_DIR}/src/queue_set.c
	${CMAKE_SOURCE_DIR}/src/utils.c		
	${CMAKE_SOURCE_DIR}/src/main.c
	${CMAKE_SOURCE_DIR}/src/trie.c
	${CMAKE_SOURCE_DIR}/src/worker_thread.c
	${CMAKE_SOURCE_DIR}/src/db_thread.c
	${CMAKE_SOURCE_DIR}/src/printer_thread.c
)

# pcap라이브러리 찾기
find_library(PCAP_LIBRARY pcap)

# find package
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)
# find_package(jemalloc REQUIRED)


add_executable(project1_psh ${SOURCES})


# lib linking
# target_link_libraries(project1_psh ${PCAP_LIBRARY} SQLite::SQLite3 Threads::Threads jemalloc)
target_link_libraries(project1_psh ${PCAP_LIBRARY} SQLite::SQLite3 Threads::Threads)


