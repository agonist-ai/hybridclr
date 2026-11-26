#include "LoadGate.h"

#include <cstring>
#include <cstdio>

#include "os/Mutex.h"
#include "Baselib.h"
#include "Cpp/ReentrantLock.h"
#include "vm/Exception.h"

namespace hybridclr
{
    static const int kMaxTickets = 8;

    static baselib::ReentrantLock s_gateLock;
    static LoadGateMode s_mode = (LoadGateMode)HYBRIDCLR_LOAD_GATE_DEFAULT;
    static uint8_t s_tickets[kMaxTickets][32];
    static int s_ticketCount = 0;
    static int32_t s_accepted = 0;
    static int32_t s_refused = 0;

    // ---- SHA-256 (FIPS 180-4) ----
    static const uint32_t K256[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    static inline uint32_t Ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    static void Sha256Block(uint32_t h[8], const uint8_t* p)
    {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) | ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
        for (int i = 16; i < 64; i++)
        {
            uint32_t s0 = Ror(w[i - 15], 7) ^ Ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = Ror(w[i - 2], 17) ^ Ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++)
        {
            uint32_t t1 = hh + (Ror(e, 6) ^ Ror(e, 11) ^ Ror(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
            uint32_t t2 = (Ror(a, 2) ^ Ror(a, 13) ^ Ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void LoadGate::Sha256(const void* data, size_t length, uint8_t out[32])
    {
        uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
        const uint8_t* p = (const uint8_t*)data;
        size_t full = length / 64;
        for (size_t i = 0; i < full; i++)
            Sha256Block(h, p + i * 64);
        uint8_t tail[128];
        size_t rest = length - full * 64;
        std::memset(tail, 0, sizeof(tail));
        if (rest)
            std::memcpy(tail, p + full * 64, rest);
        tail[rest] = 0x80;
        size_t tailLen = rest + 1 + 8 <= 64 ? 64 : 128;
        uint64_t bits = (uint64_t)length * 8;
        for (int i = 0; i < 8; i++)
            tail[tailLen - 1 - i] = (uint8_t)(bits >> (8 * i));
        Sha256Block(h, tail);
        if (tailLen == 128)
            Sha256Block(h, tail + 64);
        for (int i = 0; i < 8; i++)
        {
            out[i * 4] = (uint8_t)(h[i] >> 24);
            out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
            out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
            out[i * 4 + 3] = (uint8_t)h[i];
        }
    }

    // ---- gate ----
    LoadGateMode LoadGate::GetMode()
    {
        il2cpp::os::FastAutoLock lock(&s_gateLock);
        return s_mode;
    }

    LoadGateMode LoadGate::SetMode(LoadGateMode mode)
    {
        il2cpp::os::FastAutoLock lock(&s_gateLock);
        if ((int32_t)mode > (int32_t)s_mode && (int32_t)mode <= (int32_t)LoadGateMode::BuiltinOnly)
        {
            s_mode = mode;
            if (s_mode == LoadGateMode::BuiltinOnly)
                s_ticketCount = 0;
        }
        return s_mode;
    }

    bool LoadGate::AllowLoad(const uint8_t* sha256, size_t len)
    {
        if (!sha256 || len != 32)
            return false;
        il2cpp::os::FastAutoLock lock(&s_gateLock);
        if (s_mode == LoadGateMode::BuiltinOnly)
            return false;
        if (s_ticketCount == kMaxTickets)
        {
            std::memmove(s_tickets[0], s_tickets[1], sizeof(s_tickets[0]) * (kMaxTickets - 1));
            s_ticketCount--;
        }
        std::memcpy(s_tickets[s_ticketCount++], sha256, 32);
        return true;
    }

    void LoadGate::CheckOrRaise(const void* data, size_t length, const char* what)
    {
        const char* why = nullptr;
        {
            il2cpp::os::FastAutoLock lock(&s_gateLock);
            if (s_mode == LoadGateMode::Open)
            {
                s_accepted++;
                return;
            }
            if (s_mode == LoadGateMode::BuiltinOnly)
            {
                why = "built-in code only";
            }
            else if (!data)
            {
                why = "no bytes";
            }
            else
            {
                uint8_t sum[32];
                Sha256(data, length, sum);
                for (int i = 0; i < s_ticketCount; i++)
                {
                    if (std::memcmp(s_tickets[i], sum, 32) == 0)
                    {
                        std::memmove(s_tickets[i], s_tickets[i + 1], sizeof(s_tickets[0]) * (s_ticketCount - 1 - i));
                        s_ticketCount--;
                        s_accepted++;
                        return;
                    }
                }
                why = "no verified ticket for these bytes (HybridCLR.RuntimeApi.AllowLoad was not called with their SHA-256)";
            }
            s_refused++;
        }
        char msg[256];
        std::snprintf(msg, sizeof(msg), "hybridclr load gate refused %s: %s", what, why);
        il2cpp::vm::Exception::Raise(il2cpp::vm::Exception::GetNotSupportedException(msg));
    }

    int32_t LoadGate::Accepted()
    {
        il2cpp::os::FastAutoLock lock(&s_gateLock);
        return s_accepted;
    }

    int32_t LoadGate::Refused()
    {
        il2cpp::os::FastAutoLock lock(&s_gateLock);
        return s_refused;
    }
}
