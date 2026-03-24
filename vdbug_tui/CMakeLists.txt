cmake_minimum_required (VERSION 3.22)

project(ftxui-starter
    LANGUAGES CXX
    VERSION 1.0.0
)

find_package(ftxui REQUIRED)
add_executable(vdbug src/main.cpp)
target_link_libraries(vdbug
  PRIVATE ftxui::screen
  PRIVATE ftxui::dom
  PRIVATE ftxui::component
)
