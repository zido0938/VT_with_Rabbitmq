cmake_minimum_required(VERSION 3.10)
project(YourProjectName)

# BoostAutoChecker.cpp와 관련된 소스 파일들
set(MONITORING_SOURCES 
    BoostAutoChecker.cpp
    MerkleTreeHash.cpp
    MerkleTreeHash.h
    merklenode.h
)

# msqueue_send.cpp와 관련된 소스 파일
set(SEND_SOURCES
    msqueue_send.cpp
)

# msqueue_receive.cpp와 관련된 소스 파일
set(RECEIVE_SOURCES
    msqueue_receive.cpp
)

# monitoring 실행 파일 생성
add_executable(monitoring ${MONITORING_SOURCES})
target_include_directories(monitoring PRIVATE /usr/local/include/SimpleAmqpClient)
target_link_directories(monitoring PRIVATE /usr/local/lib)
target_link_libraries(monitoring PRIVATE SimpleAmqpClient ssl crypto boost_system boost_thread boost_chrono boost_filesystem)

# send 실행 파일 생성
add_executable(send ${SEND_SOURCES})
target_link_libraries(send PRIVATE SimpleAmqpClient)

# receive 실행 파일 생성
add_executable(receive ${RECEIVE_SOURCES})
target_link_libraries(receive PRIVATE SimpleAmqpClient)

