#pragma once

#include <stdint.h>
#include <stddef.h>

// LoadGate (agonist-ai fork): the one door through which code bytes enter the interpreter.
//
// HybridCLR runs IL by interpretation only (no native code is generated, no executable memory, no dylib).
// The gate decides which bytes may become interpreted code at all:
//   Open         — upstream behaviour: any Assembly.Load(byte[]) / LoadMetadataForAOTAssembly is accepted;
//   VerifiedOnly — a load is accepted only if the caller first registered the exact SHA-256 of these bytes
//                  with AllowLoad (one ticket, one load). The app's delivery module checks the signature, the app
//                  build and the hash, then registers the ticket: there is no other way in;
//   BuiltinOnly  — nothing is loaded; the app runs its built-in code only.
// The mode can only be tightened during a process lifetime (Open -> VerifiedOnly -> BuiltinOnly).
// The start mode is HYBRIDCLR_LOAD_GATE_DEFAULT (VerifiedOnly unless the build defines otherwise).

#ifndef HYBRIDCLR_LOAD_GATE_DEFAULT
#define HYBRIDCLR_LOAD_GATE_DEFAULT 1
#endif

namespace hybridclr
{
    enum class LoadGateMode : int32_t
    {
        Open = 0,
        VerifiedOnly = 1,
        BuiltinOnly = 2,
    };

    class LoadGate
    {
    public:
        static LoadGateMode GetMode();
        // returns the mode in force afterwards (a looser mode than the current one is ignored)
        static LoadGateMode SetMode(LoadGateMode mode);
        // registers one ticket for bytes whose SHA-256 is `sha256` (32 bytes); false if the gate is BuiltinOnly
        static bool AllowLoad(const uint8_t* sha256, size_t len);
        // called by the loaders; raises a managed exception when the bytes may not be loaded. `what` names the loader.
        static void CheckOrRaise(const void* data, size_t length, const char* what);
        // SHA-256 of a buffer (FIPS 180-4), 32 bytes into `out`
        static void Sha256(const void* data, size_t length, uint8_t out[32]);
        // counters for diagnostics: accepted / refused loads
        static int32_t Accepted();
        static int32_t Refused();
    };
}
