cmake_minimum_required(VERSION 3.5)

project(process_msg VERSION 1.0.0)

add_library(ProcessMsg SHARED
    ${PROJECT_SOURCE_DIR}/source/process_msg.cpp
)



target_include_directories(ProcessMsg
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)



find_package(OpenSSL)
if(OPENSSL_FOUND)
    target_link_libraries(ProcessMsg
        PUBLIC OpenSSL::SSL
        PUBLIC OpenSSL::Crypto
    )
else()
    message(FATAL_ERROR "Can't find OpenSSL")
endif()
