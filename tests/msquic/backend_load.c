/* No link to wtquic: RTLD_NOW must resolve the backend's own SPI imports. */
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }
    return dlclose(handle) == 0 ? 0 : 3;
}
