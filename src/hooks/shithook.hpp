#pragma once
#include <atomic>
#include <map>
#include <memory>
#include <string.h>

#define __arm__
#include "sys/mman.h"
#include <unistd.h>

#define ARM_JMP_CODE 0xE51FF004 // LDR PC, [PC, #-4]
#define PAGE_START( ptr ) reinterpret_cast< void * >( reinterpret_cast< std::uintptr_t >( ptr ) >> 12 << 12 )

namespace hook
{
    class detour
    {
      public:
        detour( void *addr_to_hook, void *jmp_to, bool enable = true )
            : hook_addr( addr_to_hook ), detour_addr( jmp_to ), hook_installed( false )
        {
            reinterpret_cast< std::uint32_t * >( jmp_code )[ 0 ] = ARM_JMP_CODE;
            reinterpret_cast< void ** >( jmp_code )[ 1 ] = jmp_to;
            memcpy( org_bytes, hook_addr, sizeof( org_bytes ) );

            reinterpret_cast< std::uint32_t * >( landing_code )[ 2 ] = ARM_JMP_CODE;
            memcpy( landing_code, org_bytes, sizeof( org_bytes ) );
            reinterpret_cast< std::uint32_t * >( landing_code )[ 3 ] =
                reinterpret_cast< std::uintptr_t >( hook_addr ) + 8;

            mprotect( PAGE_START( landing_code ), getpagesize(), PROT_EXEC | PROT_READ | PROT_WRITE );

            cacheflush( reinterpret_cast< long >( PAGE_START( landing_code ) ),
                        reinterpret_cast< long >( PAGE_START( landing_code ) ) + getpagesize(), NULL );

            if ( enable )
                install();
        }
        ~detour()
        {
            uninstall();
        }

        void install()
        {
            if ( hook_installed.load() )
                return;

            if ( !mprotect( PAGE_START( hook_addr ), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC ) )
            {
                memcpy( ( void * )( ( long )hook_addr ), jmp_code, sizeof( jmp_code ) );
                mprotect( PAGE_START( hook_addr ), getpagesize(), PROT_READ | PROT_EXEC );
                cacheflush( reinterpret_cast< long >( hook_addr ),
                            reinterpret_cast< long >( hook_addr ) + getpagesize(), NULL );
                hook_installed.exchange( true );
            }
        }

        void uninstall()
        {
            if ( !hook_installed.load() )
                return;

            if ( !mprotect( PAGE_START( hook_addr ), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC ) )
            {
                memcpy( hook_addr, org_bytes, sizeof( jmp_code ) );
                mprotect( PAGE_START( hook_addr ), getpagesize(), PROT_READ | PROT_EXEC );
                cacheflush( reinterpret_cast< long >( hook_addr ),
                            reinterpret_cast< long >( hook_addr ) + getpagesize(), NULL );
                hook_installed.exchange( false );
            }
        }

        bool installed()
        {
            return hook_installed;
        }
        void *hook_address()
        {
            return hook_addr;
        }
        void *detour_address()
        {
            return detour_addr;
        }
        void *get_func()
        {
            return reinterpret_cast< void * >( landing_code );
        }

      private:
        std::atomic< bool > hook_installed;
        void *hook_addr, *detour_addr;
        unsigned char jmp_code[ 8 ];
        unsigned char landing_code[ 16 ];
        std::uint8_t org_bytes[ sizeof( jmp_code ) ];
    };

    inline std::map< void *, std::unique_ptr< detour > > *get_hooks()
    {
        static std::map< void *, std::unique_ptr< detour > > hooks{};
        return &hooks;
    }

    template < class T, class U > inline void make_hook( T addr_to_hook, U jmp_to_addr, bool enable = true )
    {
        get_hooks()->insert( { ( void * )addr_to_hook,
                               std::make_unique< detour >( ( void * )addr_to_hook, ( void * )jmp_to_addr, enable ) } );
    }

    template < class T > inline void enable( T addr )
    {
        get_hooks()->at( ( void * )addr )->install();
    }

    template < class T > inline T get_func( T addr )
    {
        return reinterpret_cast< T >( get_hooks()->at( ( void * )addr )->get_func() );
    }

    template < class T > inline void disable( T addr )
    {
        get_hooks()->at( ( void * )addr )->uninstall();
    }

    template < class T > inline void remove( T addr )
    {
        get_hooks()->erase( ( void * )addr );
    }
} // namespace hook