cmake_minimum_required(VERSION 3.5)

project(InjectDLLApplication)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt5 COMPONENTS Widgets REQUIRED)

set(SOURCE
    mainwindow.cpp
    main.cpp
)

add_executable(InjectDLLApplication ${SOURCE})

target_link_libraries(InjectDLLApplication Qt5::Widgets)