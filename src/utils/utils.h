#pragma once
#include "../hooks/shithook.hpp"
#include <dlfcn.h>
#include <fstream>
#include <functional>
#include <inttypes.h>
#include <map>
#include <mutex>
#include <string>

namespace ligma
{
    namespace utils
    {
        inline void *dlopen_ptr = nullptr;
        std::uintptr_t get_module_base( const char *module_name );
        auto get_callbacks() -> std::map< std::string, std::function< bool( std::uintptr_t, void * ) > > *;
        void *dlopen_handler( const char *filename, int flags );
        void on_image_load( const std::string &module_name,
                            const std::function< bool( std::uintptr_t, void * ) > &callback );
    } // namespace utils
} // namespace ligma