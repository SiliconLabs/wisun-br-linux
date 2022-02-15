include(FindPackageHandleStandardArgs)
find_program(CARGO_COMMAND cargo)
mark_as_advanced(CARGO_COMMAND)

if (CARGO_COMMAND)
    execute_process(COMMAND ${CARGO_COMMAND} --version
                    OUTPUT_VARIABLE CARGO_VERSION_OUTPUT)
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+"
           CARGO_VERSION "${CARGO_VERSION_OUTPUT}")
endif()

find_package_handle_standard_args(Cargo
    REQUIRED_VARS CARGO_COMMAND
    VERSION_VAR CARGO_VERSION
)
