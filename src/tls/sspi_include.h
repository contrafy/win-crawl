#pragma once
// The SSPI/Schannel headers need a fixed include order and opt-in macros:
// SECURITY_WIN32 selects the user-mode SSPI API, SCHANNEL_USE_BLACKLISTS exposes
// SCH_CREDENTIALS (the only credential shape that can negotiate TLS 1.3), and
// that struct uses UNICODE_STRING from subauth.h.

#include <windows.h>

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS
#endif

#include <subauth.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
