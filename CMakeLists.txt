cmake_minimum_required (VERSION 3.8)

project ("khazad_dum")

add_executable (khazad_dum 
    "src/khazad_dum.cpp"
    "src/tpm2/crypt_key.cpp"
    "src/tpm2/tpm2_hal.cpp"
)

include_directories (
    "include"
    "/usr/include/tss"
)

add_subdirectory(
    libs/ext/json
)

target_link_libraries(khazad_dum
    tss2-esys
    nlohmann_json::nlohmann_json
)
