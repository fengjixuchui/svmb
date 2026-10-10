// svmb - per-process memory-block encryption (r133, dual-frame split view).
//
// enc: for every 4K page of the block, map the page's GPA to a private
// plaintext byte-copy on the target's process NPT view (NptOverlay slot -
// the r128 primitive), then write XOR-keystream ciphertext into the
// ORIGINAL physical frame through a temporary MmMapIoSpace alias. The
// target keeps reading/writing plaintext through its view; every other
// observer (readvm, physical scanners, kernel threads on other CR3s) sees
// ciphertext. Context switches cost nothing: the per-core view policy is
// resident, no data moves on enter/leave.
//
// dec: the private frame is the plaintext authority (every target write
// landed there while encrypted) - copy it back to the original frame, then
// unmap the overlay (identity restore + r130 graveyard park). The key
// never participates in decrypt.
//
// Consistency: the target is suspended across every original-frame write,
// so no guest access can race the ciphertext store (stale-TLB writes to
// the original frame are impossible while the writer set is {driver}).
// Driver unload restores every live block BEFORE freeing the overlays
// (reversed order strands ciphertext in a live frame = data loss).
//
// Hard-crash recovery is manual (documented): readvm the ciphertext, XOR
// with the block key, writevm back - the key is kept in the block record
// precisely so the operator can rebuild the stream offline.
#ifndef SVMB_MEM_CRYPT_H
#define SVMB_MEM_CRYPT_H

#include "platform/base.h"
#include "svmb_protocol.h"

namespace svmb
{

// XOR keystream, position-addressable by BLOCK offset: the same (key,
// offset) pair regenerates the identical stream, so decrypt == encrypt and
// a multi-page block is one continuous stream regardless of the per-page
// call shape. Stream unit = one splitmix-mixed 64-bit word per 8-byte
// window (little-endian byte order). key == 0 (or empty buffer) is a no-op
// so the offline tests can pin that contract; the IOCTL layer refuses
// key == 0 outright.
void CryptXorStream(u64 key, u64 blockOffset, u8* buf, u32 len);

// IOCTL_CR3_CRYPT entry point. PASSIVE_LEVEL, called under the driver IO
// gate from DevCtrlLocked. p->Action: 0 = encrypt, 1 = decrypt, 2 = list.
// OutStatus carries the pages processed (enc/dec) or the total block count
// (list); Count carries the entries filled into Blocks[] (list).
NTSTATUS MemCryptAction(SVMB_CR3_CRYPT* p);

// DriverEntry: register the process-exit notify (record sweep). Call after
// the control device exists; order-tolerant if never called.
void MemCryptLoadInit();
// DevUnload / OfflineTeardown FIRST step (before gHooks->Deinit): write
// every live block's plaintext back to its original frame, free the
// overlays outright (hypervisor stopped - freeNow, no graveyard park),
// drop all records and unregister the notify. Idempotent.
void MemCryptDeinit();

// process-exit sweep: unlink the dying pid's block RECORDS only. The
// overlays themselves are swept by npt_hook_mgr's own UserProcNotify
// (OverlayUnmapForPid); a dead target's frames are recycled by the OS, its
// ciphertext dies with them - a later Deinit must never write a recycled
// frame, which is exactly why the records go first.
void MemCryptSweepPid(u32 pid);

// live block count (list/stats disclosure)
u32 MemCryptBlockCount();

} // namespace svmb

#endif // SVMB_MEM_CRYPT_H
