# Relocatable pkg-config prefix: express the install prefix relative to
# the .pc file's own directory (${pcfiledir}), so installing with a
# different --prefix than the configured one still yields working
# --cflags/--libs. An absolute CMAKE_INSTALL_LIBDIR cannot be made
# pcfiledir-relative; fall back to the configured prefix there.
if(DEFINED WTQ_PC_PREFIX)
    return()
endif()
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
    set(WTQ_PC_PREFIX "${CMAKE_INSTALL_PREFIX}")
else()
    file(RELATIVE_PATH _wtq_pc_rel
         "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig"
         "${CMAKE_INSTALL_PREFIX}")
    string(REGEX REPLACE "/$" "" _wtq_pc_rel "${_wtq_pc_rel}")
    set(WTQ_PC_PREFIX "\${pcfiledir}/${_wtq_pc_rel}")
endif()
