#include "utils.h"
#include "../ligma.h"

namespace ligma
{
    namespace utils
    {
        std::uintptr_t get_module_base( const char *module_name )
        {
            std::unique_ptr< FILE, decltype( &fclose ) > maps_handle( fopen( "/proc/self/maps", "r" ), &fclose );
            char line[ 512 ], mod_name[ 64 ];
            std::uintptr_t base;
            while ( fgets( line, sizeof( line ), maps_handle.get() ) )
                if ( std::sscanf( line, "%" PRIXPTR "-%*" PRIXPTR " %*s %*s %*s %*s %s", &base, mod_name ) )
                    if ( std::strstr( mod_name, module_name ) )
                        return base;
            return NULL;
        }

        auto get_callbacks() -> std::map< std::string, std::function< bool( std::uintptr_t, void * ) > > *
        {
            static std::map< std::string, std::function< bool( std::uintptr_t, void * ) > > callback_map{};
            return &callback_map;
        }

        __attribute__( ( noinline ) ) void *dlopen_handler( const char *filename, int flags )
        {
            const auto result =
                reinterpret_cast< decltype( &dlopen ) >( ::hook::get_func( dlopen_ptr ) )( filename, flags );

            if ( !ligma::utils::get_callbacks()->size() )
                ::hook::disable( dlopen_ptr );

            for ( const auto &[ file_key, callback ] : *ligma::utils::get_callbacks() )
            {
                if ( std::strstr( filename, file_key.c_str() ) )
                {
                    // remove the callback before calling it, this prevents loops...
                    ligma::utils::get_callbacks()->erase( file_key );
                    if ( callback( ligma::utils::get_module_base( file_key.c_str() ), result ) )
                        on_image_load( file_key, callback ); // add it back if we still want the callback...
                    break;
                }
            }
            return result;
        }

        void on_image_load( const std::string &module_name,
                            const std::function< bool( std::uintptr_t, void * ) > &callback )
        {
            static std::once_flag once;
            std::call_once( once, [ & ]() {
                ::hook::make_hook( ( dlopen_ptr = dlsym( dlopen( "libdl.so", RTLD_NOLOAD ), "dlopen" ) ),
                                   &dlopen_handler );
            } );
            get_callbacks()->insert( { module_name, callback } );
        }
    } // namespace utils
} // namespace ligma