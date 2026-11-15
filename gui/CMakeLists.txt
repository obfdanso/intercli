# Desktop chat app (Qt Quick). Only added when Qt 6 is found.

qt_standard_project_setup(REQUIRES 6.5)
qt_policy(SET QTP0004 NEW)

# Everything except main.cpp, so the Qt tests can link it.
qt_add_library(intercli_gui_lib STATIC
    text_utils.cpp
    conversation_list_model.cpp
    message_model.cpp
)
target_include_directories(intercli_gui_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(intercli_gui_lib PUBLIC
    intercli_client_core
    Qt6::Quick
)

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
    intercli_gui_lib
    Qt6::Quick
    Qt6::QuickControls2
)

if(MSVC)
    target_compile_options(intercli_gui PRIVATE /W4)
    target_compile_options(intercli_gui_lib PRIVATE /W4)
else()
    target_compile_options(intercli_gui PRIVATE -Wall -Wextra)
    target_compile_options(intercli_gui_lib PRIVATE -Wall -Wextra)
endif()

# Qt Test programs for the app's non-visual parts. Qt's bin folder goes on PATH
# so they run without deploying Qt next to them.
function(intercli_add_qt_test name)
    qt_add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE intercli_gui_lib Qt6::Test)
    set_target_properties(${name} PROPERTIES AUTOMOC ON)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${QT6_INSTALL_PREFIX}/bin")
    if(WIN32 AND OPENSSL_RUNTIME_DLLS)
        add_custom_command(TARGET ${name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_RUNTIME_DLLS} $<TARGET_FILE_DIR:${name}>)
    endif()
endfunction()

intercli_add_qt_test(test_text_utils)
intercli_add_qt_test(test_conversation_list_model)
intercli_add_qt_test(test_message_model)

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
