cmake_minimum_required(VERSION 3.0)
project(ako)

set(CMAKE_CXX_STANDARD 17)

add_executable(ako main.cpp)

add_custom_command(TARGET ${CMAKE_PROJECT_NAME}
        POST_BUILD
        COMMAND adb push ${CMAKE_PROJECT_NAME} /data/local/tmp/${CMAKE_PROJECT_NAME} && adb shell chmod +x /data/local/tmp/${CMAKE_PROJECT_NAME}
        COMMENT "Compressing ${CMAKE_PROJECT_NAME} using UPX")