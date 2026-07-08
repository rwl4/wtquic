#ifndef WTQ_EXPORT_H
#define WTQ_EXPORT_H

/*
 * Symbol export/visibility control.
 *
 * WTQ_BUILDING is defined only while compiling the wtquic library itself.
 * All targets build with hidden default visibility; only WTQ_API symbols
 * are exported. The exported set is pinned by the symbol-policy test.
 */

#if defined(_WIN32) && !defined(WTQ_STATIC)
#  ifdef WTQ_BUILDING
#    define WTQ_API __declspec(dllexport)
#  else
#    define WTQ_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define WTQ_API __attribute__((visibility("default")))
#else
#  define WTQ_API
#endif

#endif /* WTQ_EXPORT_H */
