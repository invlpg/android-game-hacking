#pragma once
#include "shithook.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <mutex>
#include <regex>
#include <string>

namespace ligma
{
    namespace hook
    {
        inline void *dlsym_ptr = nullptr;
        void *dlsym_bypass( void *handle, const char *symbol );
        void *dlsym_handler( void *handle, const char *symbol );
        auto get_dlsym_hooks() -> std::map< std::pair< void *, std::string_view >, void * > *;
        void dlsym_unhook( const std::pair< void *, std::string_view > &symbol_data );

        template < class T > inline void dlsym_hook( std::pair< void *, const char * > symbol_data, T *function_ptr )
        {
            static std::once_flag once;
            std::call_once( once, [ & ]() {
                ::hook::make_hook( ( dlsym_ptr = dlsym( dlopen( "libdl.so", RTLD_NOW ), "dlsym" ) ), &dlsym_handler );
                ::hook::make_hook( &dlsym, &dlsym_bypass );
            } );

            get_dlsym_hooks()->insert( { { symbol_data.first, std::string_view{ symbol_data.second } },
                                         reinterpret_cast< void * >( function_ptr ) } );
        }
    } // namespace hook
} // namespace ligma