#include "dlsym_hook.h"

namespace ligma
{
    namespace hook
    {
        auto get_dlsym_hooks() -> std::map< std::pair< void *, std::string_view >, void * > *
        {
            static std::map< std::pair< void *, std::string_view >, void * > hooks{};
            return &hooks;
        }

        __attribute__( ( noinline ) ) void *dlsym_handler( void *handle, const char *symbol )
        {
            for ( const auto &[ map_handle, function_ptr ] : *get_dlsym_hooks() )
                if ( !map_handle.first || map_handle.first == handle )
                    if ( std::regex_match( symbol, std::regex( map_handle.second.data() ) ) )
                        return function_ptr;

            return reinterpret_cast< decltype( &dlsym ) >( ::hook::get_func( dlsym_ptr ) )( handle, symbol );
        }

        void dlsym_unhook( const std::pair< void *, std::string_view > &symbol_data )
        {
            get_dlsym_hooks()->erase( symbol_data );
        }
    } // namespace hook
} // namespace ligma