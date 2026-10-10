// svmb - per-process memory-block encryption (r133). See mem_crypt.h for
// the dual-frame split-view contract and docs/MEM_CRYPT.md for the design
// record. IOCTL-path module in the mem_read shape: entry points are called
// from DevCtrlLocked under the driver IO gate; no SvmbModule registration.
//
// r133 transition safety:
//  1. FROZEN stage-1: the target stays suspended from stage-1 (map) until
//     seal - it cannot migrate, execute or re-cache a stale translation.
//  2. exit-generation gate: seal stores ciphertext only after every core
//     exited once past the post-map snapshot (each exit consumed the
//     pending TLB kick = the cached GPA->original translations are gone).
//  3. VIEW-SYNC CONTRACT (r133 measured law): the per-core NCr3 is only
//     re-published at VM exits. An exitless epoch that migrated to a core
//     holding a stale base NCr3 reads the ORIGINAL frame - post-seal that
//     is ciphertext. A U/S=0 base-view trap was tried and REJECTED: the
//     r32 unconditional-fault law hits the kernel's own touchers (working
//     set / compression walks) within seconds, and resolving those faults
//     disarms the trap (kernel-log evidence, r133 round 3). Deployment
//     contract: the protected target takes one intercepted CPUID at its
//     block-access points (the sync point - see tests/mcrypt_target.c);
//     arbitrary exitless targets need the structural per-core-view fix
//     (the npt.h M4 prerequisite).
#include "modules/mem_crypt.h"
#include "modules/cr3_monitor.h" // Cr3M4ArmProcessView (process-view arm)
#include "modules/npt_hook_mgr.h" // SysAuditGlobalHooks + overlay slots
#include "core/hypervisor.h"     // r133 review P2-1: seal hv-running guard
#include "platform/logger.h"
#include "platform/util.h"

// documented kernel interfaces whose declarations live in ntifs.h -
// this driver is ntddk-only (npt_hook_mgr.cpp / mem_read.cpp pattern).
// PsSetCreateProcessNotifyRoutineEx IS declared in wdm.h - redeclaring it
// trips C4273 (dll-linkage mismatch).
extern "C" NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId,
                                               PEPROCESS* Process);

namespace svmb
{

namespace {
constexpr u64 PAGE_MASK = ~0xFFFull;

// ---- keystream core (pure, offline-tested via TestCryptStream) --------

// splitmix64 finalizer: bijective in z, avalanche-complete - two nearby
// counters (or two nearby keys) yield fully decorrelated words.
u64 Mix64(u64 z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

// stream word for 8-byte window index idx under key: position-addressable
// (O(1) jump to any offset - a multi-page block encrypts as ONE stream
// regardless of the per-page call shape; idx+1 keeps word 0 clear of the
// raw key echo)
u64 StreamWord(u64 key, u64 idx)
{
    return Mix64(key ^ ((idx + 1) * 0x9E3779B97F4A7C15ull));
}

// ---- block table -------------------------------------------------------
// Tiny bounded set (protocol Blocks[8], overlay slots cap the pages at 32
// globally): a singly-linked list guarded by one spinlock beats a hash
// table. The IOCTL side holds the driver gate; the process-exit notify
// does NOT - the spinlock is what makes the sweep safe against an
// in-flight enc/dec traversal (records are unlinked only, never mutated
// in place except the Sealed/Frozen flag stores).
struct CryptBlock
{
    CryptBlock* Next;
    u32 Pid;
    u32 PageCount;
    u32 Sealed;     // 0 = ARMED (maps live, originals plaintext, target
                    // FROZEN), 1 = SEALED (ciphertext stored, resumed)
    u64 BaseVa; // 4K aligned
    u64 Size;   // bytes, 4K multiple
    u64 Key;    // keystream key (dec never needs it - kept for the
                // hard-crash manual-recovery record)
    u64* Snap;  // post-map exit-count snapshot (seal gate; null when the
                // snapshot alloc failed - the block stays ARMED-only)
    u32 SnapCount;
    // the frozen flag tracks stage-1's outstanding suspend (seal/dec/
    // Deinit each owe exactly one resume)
    volatile LONG Frozen;
};

KSPIN_LOCK g_blockLock;
CryptBlock* g_blocks = nullptr;
u32 g_blockCount = 0;
bool g_inited = false;

// ---- suspend primitives (cr3_monitor.cpp:2725 precedent: dynamic
// resolution, degraded continue - the LOGW tells the operator the
// consistency guarantee weakened) ----------------------------------------
typedef NTSTATUS (*SUSPEND_FN)(PEPROCESS);
SUSPEND_FN g_pfnSuspend = nullptr;
SUSPEND_FN g_pfnResume = nullptr;
volatile LONG g_suspTried = 0;

bool ResolveSuspendFns()
{
    if (InterlockedCompareExchange(&g_suspTried, 1, 0) == 0)
    {
        UNICODE_STRING fnSus = RTL_CONSTANT_STRING(L"PsSuspendProcess");
        UNICODE_STRING fnRes = RTL_CONSTANT_STRING(L"PsResumeProcess");
        g_pfnSuspend = (SUSPEND_FN)MmGetSystemRoutineAddress(&fnSus);
        g_pfnResume = (SUSPEND_FN)MmGetSystemRoutineAddress(&fnRes);
        if (!g_pfnSuspend || !g_pfnResume)
            SVMB_LOGW("memcrypt: suspend unavailable (%s%s) - frame writes "
                      "run unsuspended",
                      g_pfnSuspend ? "" : " no PsSuspendProcess",
                      g_pfnResume ? "" : " no PsResumeProcess");
    }
    return g_pfnSuspend && g_pfnResume;
}

// ---- physical write: the ONLY channel that touches the original frame.
// A page-length MmMapIoSpace alias is address-space-independent (no CR3,
// no NPT view) - deterministic landing on the frame regardless of which
// view the faulting core would have used.
bool PhysWrite(u64 pa, const void* src, u32 len)
{
    if (!pa || !src || !len)
        return false;
    PHYSICAL_ADDRESS phys = {};
    phys.QuadPart = static_cast<LONGLONG>(pa);
    void* map = MmMapIoSpace(phys, len, MmCached);
    if (!map)
    {
        SVMB_LOGW("memcrypt: MmMapIoSpace refused pa=%llx len=%u", pa, len);
        return false;
    }
    __try
    {
        RtlCopyMemory(map, src, len);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        MmUnmapIoSpace(map, len);
        return false;
    }
    MmUnmapIoSpace(map, len);
    return true;
}

// ---- block-table helpers (g_blockLock held by caller unless noted) -----

CryptBlock* FindBlockLocked(u32 pid, u64 baseVa)
{
    for (CryptBlock* b = g_blocks; b; b = b->Next)
        if (b->Pid == pid && b->BaseVa == baseVa)
            return b;
    return nullptr;
}

static void FreeBlockRecord(CryptBlock* b); // owns the snapshot too

bool AddBlock(u32 pid, u64 baseVa, u64 size, u64 key, u32 pages, u64* snap,
              u32 snapCount)
{
    CryptBlock* b = (CryptBlock*)AllocNonPaged(sizeof(*b), TAG_MCRT);
    if (!b)
    {
        if (snap)
            NptHookManager::OverlayFreeGeneration(snap);
        return false; // no record = no future dec - undo the encryption
    }
    RtlZeroMemory(b, sizeof(*b));
    b->Pid = pid;
    b->BaseVa = baseVa;
    b->Size = size;
    b->Key = key;
    b->PageCount = pages;
    b->Snap = snap;
    b->SnapCount = snapCount;
    b->Frozen = 1; // stage-1 leaves the target suspended
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&g_blockLock, &irql);
    b->Next = g_blocks;
    g_blocks = b;
    ++g_blockCount;
    KeReleaseSpinLock(&g_blockLock, irql);
    return true;
}

// copy-out lookup: the caller operates on the SNAPSHOT outside the lock
bool SnapshotBlock(u32 pid, u64 baseVa, CryptBlock& out)
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&g_blockLock, &irql);
    CryptBlock* b = FindBlockLocked(pid, baseVa);
    bool ok = b != nullptr;
    if (ok)
        out = *b;
    KeReleaseSpinLock(&g_blockLock, irql);
    return ok;
}

bool BlockExists(u32 pid, u64 baseVa)
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&g_blockLock, &irql);
    bool ok = FindBlockLocked(pid, baseVa) != nullptr;
    KeReleaseSpinLock(&g_blockLock, irql);
    return ok;
}

// ARMED -> SEALED completion: flag, snapshot release, freeze release
void MarkBlockSealed(u32 pid, u64 baseVa)
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&g_blockLock, &irql);
    if (CryptBlock* b = FindBlockLocked(pid, baseVa))
    {
        b->Sealed = 1;
        InterlockedExchange(&b->Frozen, 0);
        // the generation snapshot served its purpose
        if (b->Snap)
        {
            NptHookManager::OverlayFreeGeneration(b->Snap);
            b->Snap = nullptr;
            b->SnapCount = 0;
        }
    }
    KeReleaseSpinLock(&g_blockLock, irql);
}

// r133 review P0-2: clear the stage-1 freeze on the LIVE record after a
// path paid its resume while keeping the record (failed dec) - a retry
// must not pay the owed suspend again, and a later seal must not assume
// the target is still frozen
void ClearFrozen(u32 pid, u64 baseVa)
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&g_blockLock, &irql);
    if (CryptBlock* b = FindBlockLocked(pid, baseVa))
        InterlockedExchange(&b->Frozen, 0);
    KeReleaseSpinLock(&g_blockLock, irql);
}

void RemoveBlock(u32 pid, u64 baseVa)
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&g_blockLock, &irql);
    CryptBlock** pp = &g_blocks;
    while (*pp)
    {
        CryptBlock* b = *pp;
        if (b->Pid == pid && b->BaseVa == baseVa)
        {
            *pp = b->Next;
            --g_blockCount;
            KeReleaseSpinLock(&g_blockLock, irql);
            FreeBlockRecord(b);
            return;
        }
        pp = &b->Next;
    }
    KeReleaseSpinLock(&g_blockLock, irql);
}

// free a record + its generation snapshot (every ownership exit funnels
// here so the snapshot can never outlive its block)
static void FreeBlockRecord(CryptBlock* b)
{
    if (b->Snap)
        NptHookManager::OverlayFreeGeneration(b->Snap);
    FreeNonPaged(b, TAG_MCRT);
}

// ---- enc/dec cores -----------------------------------------------------

// undo every page of a failed stage-1 up to and INCLUDING page index
// `last` (the failing page may have mapped): the unmap (identity restore
// + pin release + park) always runs - the originals were never ciphered
// at stage-1, so no write-back exists. Pages whose overlay is already
// gone (target died mid-loop and the notify swept it) skip - their
// frames were recycled.
void CryptRollback(NptHookManager* hooks, u32 pid, u64 baseVa, u32 last)
{
    for (u32 i = 0; i <= last; ++i)
    {
        u64 pageVa = baseVa + (u64)i * 0x1000;
        // unmap is self-guarding: a page whose overlay already went
        // away (target died mid-loop and the notify swept it) refuses
        // with NOT_FOUND - nothing to undo for it
        NTSTATUS st = hooks->OverlaySlotUnmap(pid, pageVa);
        if (!NT_SUCCESS(st) && st != STATUS_NOT_FOUND)
            SVMB_LOGW("memcrypt: rollback unmap st=%08x va=%llx", st,
                      pageVa);
    }
}

// stage 1 of the r133 two-phase enc: suspend -> arm view -> map every
// page's private plaintext copy (OverlaySlotMap: copy + pin + view swap
// + TLB kick) -> snapshot the per-vcpu exit counts (AFTER the kicks) ->
// record the block as ARMED+FROZEN and RETURN WITHOUT RESUMING.
//
// The target stays frozen until seal (or dec/failure cleanup): while
// frozen it cannot migrate, execute or re-cache a stale GPA->original
// translation between the gate and the ciphertext store. The ORIGINAL
// frames stay plaintext here - any not-yet-flushed translation still
// reads correctly.
//
// FROZEN crash safety: every exit from ARMED (seal, dec, failure
// rollback, Deinit, exit-notify sweep) MUST resume exactly once - the
// Frozen flag tracks the outstanding suspend.
NTSTATUS CryptEnc(SVMB_CR3_CRYPT* p)
{
    if (!p->Pid || !p->Key || !p->BaseVa)
        return STATUS_INVALID_PARAMETER;
    if (IsKernelVa(p->BaseVa) || (p->BaseVa & ~PAGE_MASK)
        || (p->Size & ~PAGE_MASK) || !p->Size)
        return STATUS_INVALID_PARAMETER;
    const u32 pages = (u32)(p->Size >> 12);
    if (pages > SVMB_CRYPT_MAX_PAGES)
        return STATUS_INVALID_PARAMETER;
    if (BlockExists(p->Pid, p->BaseVa))
        return STATUS_OBJECT_NAME_COLLISION;

    NptHookManager* hooks = SysAuditGlobalHooks();
    if (!hooks)
        return STATUS_DEVICE_NOT_READY;

    PEPROCESS proc = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)p->Pid,
                                               &proc))
        || !proc)
        return STATUS_INVALID_PARAMETER;

    // arm the target's process view (idempotent; the r120 single binding
    // slot refuses a second concurrent LIVE target with DEVICE_BUSY)
    u32 viewId = 0;
    NTSTATUS st = Cr3M4ArmProcessView(p->Pid, &viewId);
    if (!NT_SUCCESS(st))
    {
        ObDereferenceObject(proc);
        return st;
    }

    // the stage-1 freeze is LOAD-BEARING (the seal-time ciphertext store
    // relies on the writer set being {driver}) - an unavailable or
    // failing PsSuspendProcess means the guarantee cannot be given, and
    // proceeding with Frozen=1 set would lie to seal (review P1-2)
    if (!ResolveSuspendFns()
        || !NT_SUCCESS(g_pfnSuspend(proc)))
    {
        SVMB_LOGW("memcrypt: stage-1 suspend unavailable/failed pid=%u - "
                  "refusing (freeze is load-bearing)",
                  p->Pid);
        ObDereferenceObject(proc);
        return STATUS_UNSUCCESSFUL;
    }

    SVMB_LOGI("memcrypt enc(stage1): pid=%u base=%llx pages=%u view=%u",
              p->Pid, p->BaseVa, pages, viewId);

    NTSTATUS fail = STATUS_SUCCESS;
    u32 done = 0;
    for (; NT_SUCCESS(fail) && done < pages; ++done)
    {
        const u64 pageVa = p->BaseVa + (u64)done * 0x1000;
        fail = hooks->OverlaySlotMap(p->Pid, pageVa, 0, viewId);
        if (NT_SUCCESS(fail))
        {
            // resolve the dual frame now so seal cannot race a lookup
            u64 origPa = 0;
            void* privVa = nullptr;
            if (!hooks->OverlayLookupFrame(p->Pid, pageVa, origPa,
                                           &privVa))
                fail = STATUS_UNSUCCESSFUL; // map raced a process exit
        }
    }

    if (NT_SUCCESS(fail))
    {
        u32 snapCount = 0;
        u64* snap = hooks->OverlayArmGeneration(snapCount);
        if (!AddBlock(p->Pid, p->BaseVa, p->Size, p->Key, pages, snap,
                      snapCount))
        {
            // no record = no future dec - undo the maps
            SVMB_LOGW("memcrypt: record alloc failed - rolling back");
            CryptRollback(hooks, p->Pid, p->BaseVa, done ? done - 1 : 0);
            (void)g_pfnResume(proc); // the freeze is guaranteed here
            fail = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            p->OutStatus = done;
            SVMB_LOGI("memcrypt enc ARMED+FROZEN: pid=%u pages=%u (seal "
                      "pending)",
                      p->Pid, done);
            // success: target stays FROZEN - seal/dec owns the resume
            ObDereferenceObject(proc);
            return STATUS_SUCCESS;
        }
    }
    else
    {
        SVMB_LOGW("memcrypt enc FAILED at page %u st=%08x - rolling back",
                  done, fail);
        CryptRollback(hooks, p->Pid, p->BaseVa, done);
        (void)g_pfnResume(proc); // the freeze is guaranteed here
    }

    ObDereferenceObject(proc);
    return fail;
}

// stage 2: gate -> per-page ciphertext store -> THE resume owed since
// stage-1. The gate (every core exited past the post-map snapshot)
// proves no cached GPA->original translation survives the transition.
// The target is FROZEN throughout - the writer set is {driver}.
//
// STATUS_DEVICE_BUSY = cores not yet past (caller nudges + retries).
// Idempotent on sealed blocks. Partial failure keeps the block ARMED
// (mixed pages are consistent: unsealed originals stay plaintext) and
// FROZEN - dec restores/resumes from any partial state.
NTSTATUS CryptSeal(SVMB_CR3_CRYPT* p)
{
    NptHookManager* hooks = SysAuditGlobalHooks();
    if (!hooks)
        return STATUS_DEVICE_NOT_READY;
    // review P2-1: sealing into a stopped-hypervisor world would write
    // ciphertext with no NPT redirection live (the gate also trivially
    // passes when !IsRunning) - refuse; dec stays allowed (it is the
    // recovery path)
    Hypervisor* hv = Hypervisor::Instance();
    if (!hv || !hv->IsRunning())
        return STATUS_DEVICE_NOT_READY;

    // the whole gate decision runs UNDER the block lock (review P1-1):
    // SnapshotBlock would hand the Snap pointer out of the lock where
    // the exit-notify sweep could free it mid-check. OverlayGeneration-
    // Passed is a lock-free ForEachVcpu walk - legal under our spinlock.
    // Only after the gate passes do we copy the fields; the snapshot is
    // not consulted past this point.
    CryptBlock b;
    NTSTATUS st = STATUS_DEVICE_BUSY;
    {
        KIRQL irql = KeGetCurrentIrql();
        KeAcquireSpinLock(&g_blockLock, &irql);
        CryptBlock* live = FindBlockLocked(p->Pid, p->BaseVa);
        if (!live)
            st = STATUS_NOT_FOUND;
        else if (live->Sealed)
        {
            p->OutStatus = live->PageCount;
            st = STATUS_SUCCESS; // idempotent
        }
        else if (!live->Snap || !live->SnapCount)
            st = STATUS_UNSUCCESSFUL; // gate snapshot missing - dec instead
        else if (!NptHookManager::OverlayGenerationPassed(live->Snap,
                                                          live->SnapCount))
        {
            p->OutStatus = 1; // cores pending (disclosure-only count)
        }
        else
        {
            b = *live; // fields only - Snap use ends at the gate
            st = STATUS_MORE_PROCESSING_REQUIRED; // proceed marker
        }
        KeReleaseSpinLock(&g_blockLock, irql);
    }
    if (st != STATUS_MORE_PROCESSING_REQUIRED)
        return st;

    PEPROCESS proc = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)p->Pid,
                                               &proc))
        || !proc)
    {
        // dead target (killed while frozen): overlays were swept by the
        // hook manager's notify; only the record lingers
        RemoveBlock(p->Pid, p->BaseVa);
        return STATUS_NOT_FOUND;
    }

    SVMB_LOGI("memcrypt seal: pid=%u base=%llx pages=%u", b.Pid, b.BaseVa,
              b.PageCount);

    u8* scratch = (u8*)AllocNonPaged(0x1000, TAG_MCRT);
    NTSTATUS fail = scratch ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    u32 done = 0;
    for (; NT_SUCCESS(fail) && done < b.PageCount; ++done)
    {
        const u64 pageVa = b.BaseVa + (u64)done * 0x1000;
        u64 origPa = 0;
        void* privVa = nullptr;
        if (!hooks->OverlayLookupFrame(b.Pid, pageVa, origPa, &privVa))
        {
            fail = STATUS_UNSUCCESSFUL; // overlay vanished (exit sweep)
            break;
        }
        // ciphertext = keystream(plaintext snapshot from the private copy)
        RtlCopyMemory(scratch, privVa, 0x1000);
        CryptXorStream(b.Key, (u64)done * 0x1000, scratch, 0x1000);
        if (!PhysWrite(origPa, scratch, 0x1000))
        {
            fail = STATUS_UNSUCCESSFUL;
            break;
        }
    }

    if (scratch)
        FreeNonPaged(scratch, TAG_MCRT);

    if (NT_SUCCESS(fail))
    {
        // THE resume owed since stage-1 (mark first, resume last - a
        // race with dec seeing Frozen mid-transition is impossible under
        // the IOCTL gate)
        MarkBlockSealed(p->Pid, p->BaseVa);
        if (g_pfnResume)
            (void)g_pfnResume(proc);
        p->OutStatus = done;
        SVMB_LOGI("memcrypt SEALED: pid=%u pages=%u (resumed)", b.Pid,
                  done);
    }
    else
    {
        // partial seal: mixed pages consistent, block ARMED+FROZEN for a
        // retry or dec (dec restores/resumes from any partial state)
        SVMB_LOGW("memcrypt seal FAILED at page %u st=%08x (block kept "
                  "ARMED+FROZEN)",
                  done, fail);
    }
    ObDereferenceObject(proc);
    return fail;
}

// dec: the private frame IS the plaintext authority - copy it back and
// unmap (identity restore + r130 park). Key-free, works from any partial
// enc/seal state, and releases the stage-1 freeze.
NTSTATUS CryptDec(SVMB_CR3_CRYPT* p)
{
    CryptBlock b;
    if (!SnapshotBlock(p->Pid, p->BaseVa, b))
        return STATUS_NOT_FOUND;

    NptHookManager* hooks = SysAuditGlobalHooks();
    if (!hooks)
        return STATUS_DEVICE_NOT_READY;

    PEPROCESS proc = nullptr;
    const bool alive = NT_SUCCESS(
                           PsLookupProcessByProcessId(
                               (HANDLE)(ULONG_PTR)p->Pid, &proc))
                       && proc;
    if (!alive)
    {
        // dead target (killed while armed/sealed): overlays already
        // swept; only the record lingers. The freeze died with the
        // process.
        RemoveBlock(p->Pid, p->BaseVa);
        return STATUS_NOT_FOUND;
    }

    const bool wasFrozen = b.Frozen != 0;
    const bool canSuspend = ResolveSuspendFns();
    if (canSuspend)
        (void)g_pfnSuspend(proc);

    SVMB_LOGI("memcrypt dec: pid=%u base=%llx pages=%u sealed=%u", b.Pid,
              b.BaseVa, b.PageCount, b.Sealed);

    u8* scratch = (u8*)AllocNonPaged(0x1000, TAG_MCRT);
    NTSTATUS fail = scratch ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    u32 done = 0;
    for (; NT_SUCCESS(fail) && done < b.PageCount; ++done)
    {
        const u64 pageVa = b.BaseVa + (u64)done * 0x1000;
        u64 origPa = 0;
        void* privVa = nullptr;
        if (!hooks->OverlayLookupFrame(b.Pid, pageVa, origPa, &privVa))
        {
            fail = STATUS_UNSUCCESSFUL; // overlay vanished (exit sweep)
            break;
        }
        // every target write landed on the private frame while encrypted;
        // restore it, then unmap
        RtlCopyMemory(scratch, privVa, 0x1000);
        if (!PhysWrite(origPa, scratch, 0x1000))
        {
            fail = STATUS_UNSUCCESSFUL;
            break;
        }
        fail = hooks->OverlaySlotUnmap(b.Pid, pageVa);
        if (!NT_SUCCESS(fail))
            break;
    }

    if (NT_SUCCESS(fail))
    {
        RemoveBlock(b.Pid, b.BaseVa);
        p->OutStatus = done;
        SVMB_LOGI("memcrypt dec ok: pid=%u pages=%u", b.Pid, done);
    }
    else
    {
        // partial decrypt is CONSISTENT (restored pages plaintext in
        // every world; unrestored pages keep the split view) - the record
        // stays so a retry finishes the remainder
        SVMB_LOGW("memcrypt dec FAILED at page %u st=%08x (block kept)",
                  done, fail);
        p->OutStatus = done;
    }

    if (scratch)
        FreeNonPaged(scratch, TAG_MCRT);
    // the resume bookkeeping: one for dec's own suspend, one more when
    // the stage-1 freeze was still outstanding. The FAILURE path keeps
    // the record - clearing its Frozen flag after paying is what keeps a
    // retry (or a later seal) from double-paying or assuming a freeze
    // that no longer exists (review P0-2)
    if (canSuspend)
    {
        (void)g_pfnResume(proc);
        if (wasFrozen)
        {
            (void)g_pfnResume(proc);
            if (!NT_SUCCESS(fail))
                ClearFrozen(p->Pid, p->BaseVa);
        }
    }
    ObDereferenceObject(proc);
    return fail;
}

} // namespace

// ---- pure keystream (exported for offline tests) ------------------------
void CryptXorStream(u64 key, u64 blockOffset, u8* buf, u32 len)
{
    if (!key || !buf || !len)
        return;
    u64 wi = blockOffset >> 3; // current 8-byte stream window
    u32 skip = (u32)(blockOffset & 7); // bytes already consumed in it
    u32 done = 0;
    while (done < len)
    {
        const u64 w = StreamWord(key, wi);
        const u8* wb = (const u8*)&w; // little-endian byte order
        while (skip < 8 && done < len)
            buf[done++] ^= wb[skip++];
        skip = 0;
        ++wi;
    }
}

// ---- process-exit sweep -------------------------------------------------

namespace
{
VOID MemCryptNotify(PEPROCESS, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{
    if (info)
        return; // creation: nothing to do
    MemCryptSweepPid((u32)(ULONG_PTR)pid);
}
} // namespace

void MemCryptSweepPid(u32 pid)
{
    if (!g_inited || !pid)
        return;
    // collect + unlink under the lock, free outside it (records are
    // bounded by the overlay-slot ceiling)
    CryptBlock* victims[SVMB_CRYPT_MAX_PAGES];
    u32 n = 0;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&g_blockLock, &irql);
    CryptBlock** pp = &g_blocks;
    while (*pp)
    {
        CryptBlock* b = *pp;
        if (b->Pid == pid)
        {
            *pp = b->Next;
            --g_blockCount;
            if (n < SVMB_CRYPT_MAX_PAGES)
                victims[n++] = b;
        }
        else
            pp = &b->Next;
    }
    KeReleaseSpinLock(&g_blockLock, irql);
    // the overlays themselves were swept by npt_hook_mgr's own notify;
    // only the records are ours. The freeze died with the process
    // (termination proceeds on suspended processes).
    for (u32 i = 0; i < n; ++i)
        FreeBlockRecord(victims[i]);
}

u32 MemCryptBlockCount()
{
    return g_blockCount;
}

// ---- lifecycle ----------------------------------------------------------

void MemCryptLoadInit()
{
    KeInitializeSpinLock(&g_blockLock);
    g_inited = true;
    // register after the state exists; a failed registration only costs
    // the stale-record sweep (Deinit's LookupFrame-null skip is the real
    // safety net against dead-target frames)
    NTSTATUS st = PsSetCreateProcessNotifyRoutineEx(MemCryptNotify, FALSE);
    if (!NT_SUCCESS(st))
        SVMB_LOGW("memcrypt: process notify refused st=%08x - dead-target "
                  "records linger until dec/unload", st);
}

void MemCryptDeinit()
{
    if (!g_inited)
        return;
    // no new sweeps once teardown begins (unregister drains in-flight
    // callbacks before returning)
    PsSetCreateProcessNotifyRoutineEx(MemCryptNotify, TRUE);
    g_inited = false;

    NptHookManager* hooks = SysAuditGlobalHooks();
    if (!hooks)
    {
        // hook manager already gone (DriverEntry failure ordering): only
        // the records need dropping
        KIRQL irql = KeGetCurrentIrql();
        KeAcquireSpinLock(&g_blockLock, &irql);
        CryptBlock* b = g_blocks;
        g_blocks = nullptr;
        g_blockCount = 0;
        KeReleaseSpinLock(&g_blockLock, irql);
        while (b)
        {
            CryptBlock* next = b->Next;
            FreeBlockRecord(b);
            b = next;
        }
        return;
    }

    u8* scratch = (u8*)AllocNonPaged(0x1000, TAG_MCRT);
    if (!scratch)
    {
        // cannot write back - the overlays still get freed (freeNow),
        // ciphertext strands in the frames; the block keys live in the
        // log trail. Loud, never silent.
        SVMB_LOGE("memcrypt: deinit scratch alloc FAILED - plaintext "
                  "restore impossible, ciphertext WILL strand");
    }

    // ORDER LAW (review P0-1 restructure): OverlayUnmapForPid(pid, true)
    // ignores the pid - ONE call detaches and frees EVERY overlay (the
    // Deinit semantics: the hypervisor is stopping). Doing it per block
    // freed the second block's private plaintext frame before its
    // restore ran = data loss. So: phase A restores EVERY block and
    // releases every freeze FIRST; only then phase B frees the overlays
    // (once - pid 0 = clear all) and the records.
    CryptBlock* restoreList = nullptr;
    {
        KIRQL irql = KeGetCurrentIrql();
        KeAcquireSpinLock(&g_blockLock, &irql);
        restoreList = g_blocks;
        g_blocks = nullptr;
        g_blockCount = 0;
        KeReleaseSpinLock(&g_blockLock, irql);
    }
    for (CryptBlock* b = restoreList; b; b = b->Next)
    {
        if (scratch)
        {
            for (u32 i = 0; i < b->PageCount; ++i)
            {
                const u64 pageVa = b->BaseVa + (u64)i * 0x1000;
                u64 origPa = 0;
                void* privVa = nullptr;
                if (!hooks->OverlayLookupFrame(b->Pid, pageVa, origPa,
                                               &privVa))
                    continue; // swept earlier (exit notify) - skip
                RtlCopyMemory(scratch, privVa, 0x1000);
                if (!PhysWrite(origPa, scratch, 0x1000))
                    SVMB_LOGW("memcrypt: deinit restore FAILED pa=%llx",
                              origPa);
            }
        }
        // release an outstanding stage-1 freeze (alive targets only)
        if (b->Frozen && g_pfnResume)
        {
            PEPROCESS proc = nullptr;
            if (NT_SUCCESS(PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)b->Pid, &proc))
                && proc)
            {
                (void)g_pfnResume(proc);
                ObDereferenceObject(proc);
                SVMB_LOGW("memcrypt: deinit resumed frozen pid=%u",
                          b->Pid);
            }
        }
        SVMB_LOGI("memcrypt: deinit restored pid=%u base=%llx pages=%u",
                  b->Pid, b->BaseVa, b->PageCount);
    }
    // phase B: every plaintext is back in its original frame - the
    // overlays (all of them, any owner: the hook manager dies next in
    // OfflineTeardown anyway) and the records can go
    hooks->OverlayUnmapForPid(0, true);
    while (restoreList)
    {
        CryptBlock* next = restoreList->Next;
        FreeBlockRecord(restoreList);
        restoreList = next;
    }
    if (scratch)
        FreeNonPaged(scratch, TAG_MCRT);
}

// ---- IOCTL entry ---------------------------------------------------------

NTSTATUS MemCryptAction(SVMB_CR3_CRYPT* p)
{
    if (!p)
        return STATUS_INVALID_PARAMETER;
    if (!g_inited)
        return STATUS_DEVICE_NOT_READY;
    switch (p->Action)
    {
    case 0:
        p->OutStatus = 0;
        return CryptEnc(p);
    case 1:
        p->OutStatus = 0;
        return CryptDec(p);
    case 3:
        p->OutStatus = 0;
        return CryptSeal(p);
    case 2:
    {
        KIRQL irql = KeGetCurrentIrql();
        KeAcquireSpinLock(&g_blockLock, &irql);
        p->OutStatus = g_blockCount;
        u32 n = 0;
        for (CryptBlock* b = g_blocks; b && n < SVMB_CRYPT_MAX_BLOCKS;
             b = b->Next, ++n)
        {
            p->Blocks[n].Pid = b->Pid;
            p->Blocks[n].Pages = b->PageCount;
            p->Blocks[n].BaseVa = b->BaseVa;
            p->Blocks[n].Size = b->Size;
        }
        KeReleaseSpinLock(&g_blockLock, irql);
        p->Count = n;
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

} // namespace svmb
