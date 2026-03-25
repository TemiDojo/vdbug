cmake_minimum_required (VERSION 3.22)

project(vdbug_tui
    LANGUAGES CXX
    VERSION 1.0.0
)

set(SOURCES
    src/padding.cpp
    src/helpers.cpp
)

find_package(ftxui REQUIRED)
add_executable(vdbug src/main.cpp ${SOURCES})
target_link_libraries(vdbug
  PRIVATE ftxui::screen
  PRIVATE ftxui::dom
  PRIVATE ftxui::component
)

target_include_directories(vdbug 
    PRIVATE src/inc
)
