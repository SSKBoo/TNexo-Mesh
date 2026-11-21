cmake_minimum_required(VERSION 3.22.1)
project(nexomesh)

add_library(nexomesh_core STATIC IMPORTED)
set_target_properties(nexomesh_core PROPERTIES IMPORTED_LOCATION
    ${CMAKE_CURRENT_SOURCE_DIR}/../../jniLibs/${ANDROID_ABI}/libnexomesh_core.a)

target_link_libraries(nexomesh_core)
