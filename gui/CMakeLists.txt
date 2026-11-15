# Desktop chat app (Qt Quick). Only added when Qt 6 is found.

qt_standard_project_setup(REQUIRES 6.5)
qt_policy(SET QTP0004 NEW)

qt_add_executable(intercli_gui WIN32
    main.cpp
)
# Next to server.exe and client.exe (build/Release/intercli.exe).
set_target_properties(intercli_gui PROPERTIES
    OUTPUT_NAME intercli
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

set_source_files_properties(qml/Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)

qt_add_qml_module(intercli_gui
    URI Intercli
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/Theme.qml
    RESOURCES
        fonts/InterVariable.ttf
)

target_link_libraries(intercli_gui PRIVATE
    Qt6::Quick
    Qt6::QuickControls2
)

if(MSVC)
    target_compile_options(intercli_gui PRIVATE /W4)
else()
    target_compile_options(intercli_gui PRIVATE -Wall -Wextra)
endif()

if(WIN32)
    # Copy Qt's DLLs and QML modules next to intercli.exe so it runs without Qt on PATH.
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${QT6_INSTALL_PREFIX}/bin" REQUIRED)
    add_custom_command(TARGET intercli_gui POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}"
                $<IF:$<CONFIG:Debug>,--debug,--release>
                --no-translations --no-system-d3d-compiler --no-opengl-sw
                --qmldir "${CMAKE_CURRENT_SOURCE_DIR}/qml"
                "$<TARGET_FILE:intercli_gui>"
        COMMENT "Deploying Qt next to intercli.exe")
    if(OPENSSL_RUNTIME_DLLS)
        add_custom_command(TARGET intercli_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_RUNTIME_DLLS} $<TARGET_FILE_DIR:intercli_gui>)
    endif()
endif()
