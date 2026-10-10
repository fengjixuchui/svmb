/* mcrypt_target.c - r133 mem_crypt guest-side target.
 *
 * Allocates one private page, fills it with a fixed pattern, prints its
 * pid / VA / first 16 bytes (handshake side-channel: mcrypt_va.txt),
 * then self-checks every 2s until killed: while an r133 `crypt enc` is
 * live the target MUST keep seeing the PLAINTEXT pattern (its process
 * view routes the page to the private plaintext frame), while the
 * operator's readvm sees ciphertext.
 *
 * Build (host, VS dev env):  cl /W4 /O2 mcrypt_target.c
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    /* r133 review P0-1 regression shape: TWO separate pages so the
     * suite exercises multi-BLOCK enc/dec/unload (the deinit restore
     * must survive the freeNow clear-all) */
    unsigned char* p[2] = {0, 0};
    for (int k = 0; k < 2; ++k)
    {
        p[k] = (unsigned char*)VirtualAlloc(
            NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!p[k])
        {
            printf("[!] VirtualAlloc #%d failed err=%lu\n", k,
                   GetLastError());
            return 1;
        }
        for (int i = 0; i < 0x1000; ++i)
            p[k][i] = (unsigned char)(i * 31 + 7);
    }

    printf("MCRYPT-TARGET pid=%lu va1=0x%llx va2=0x%llx\n",
           (unsigned long)GetCurrentProcessId(),
           (unsigned long long)(uintptr_t)p[0],
           (unsigned long long)(uintptr_t)p[1]);
    fflush(stdout);
    /* handshake side-channel: a tiny CLOSED file (no open-handle sharing
     * with the live stdout stream) the operator polls for pid+va */
    {
        FILE* hf = fopen("mcrypt_va.txt", "w");
        if (hf)
        {
            fprintf(hf, "%lu %llx %llx\n",
                    (unsigned long)GetCurrentProcessId(),
                    (unsigned long long)(uintptr_t)p[0],
                    (unsigned long long)(uintptr_t)p[1]);
            fclose(hf);
        }
    }

    for (;;)
    {
        /* r133 view-sync point: one intercepted CPUID per check epoch.
         * The per-core NPT view policy re-publishes at every VM exit -
         * this exit lands on the CURRENT core with THIS process's CR3,
         * so the ProcView (plaintext private frame) is live before the
         * check loop walks the page. Without it, an exitless epoch that
         * migrated to a core still holding a stale base NCr3 reads the
         * original frame - post-seal that is ciphertext (the documented
         * r120-model sync contract, see docs/MEM_CRYPT.md). */
        int regs[4];
        __cpuid(regs, 1);
        /* integrity: pattern must hold on every page at every probe (a
         * target-side read of CIPHERTEXT or zeros means the split view
         * leaked */
        int bad = 0;
        for (int k = 0; k < 2; ++k)
            for (int i = 0; i < 0x1000; ++i)
                if (p[k][i] != (unsigned char)(i * 31 + 7))
                {
                    ++bad;
                    if (bad < 4)
                        printf("[!] page%d byte %d = %02x (want %02x)\n",
                               k, i, p[k][i],
                               (unsigned char)(i * 31 + 7));
                }
        printf("MCRYPT-SELF pid=%lu %s first16=",
               (unsigned long)GetCurrentProcessId(),
               bad ? "PLAINTEXT-DAMAGED" : "plaintext-ok");
        for (int i = 0; i < 16; ++i)
            printf("%02x", p[0][i]);
        printf("\n");
        fflush(stdout);
        Sleep(2000);
    }
}
