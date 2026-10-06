// Package journal stores private, local coordination checkpoints. It is not an
// Orka Task journal or verification evidence store. Phase and Data are opaque
// caller-owned coordination state, not proof that execution, verification, or
// publication succeeded. Callers should record authoritative IDs and artifact
// digests and revalidate that evidence with its owner before taking action.
//
// Create requires a new, absolute, already-clean directory path with existing
// ancestors; it never adopts or overwrites an existing directory. No component
// may be a symlink. The journal directory must be owned by the effective user
// with exactly 0700 permissions. Every entry must be an owned, single-link
// regular file with exactly 0600 permissions. Existing permissions are never
// repaired. Ancestors need not be private, but operations are directory-FD
// relative and recheck the directory's path and identity.
//
// On Linux an exclusive, nonblocking flock on the directory inode is held for
// the Store's lifetime. Close explicitly unlocks before closing the descriptor,
// so a child between fork and exec cannot extend ownership past Close. On abrupt
// process exit, the kernel releases the lock when all inherited copies close;
// descriptors are close-on-exec. A second Open, even in the same process,
// returns ErrLocked. Methods on one Store are serialized; only one Commit for a
// given expected revision can succeed. Other operating systems fail closed with
// ErrUnsupported.
//
// Version 1 starts at revision 1, phase "ingested", with a random run ID.
// Checkpoints and artifacts are immutable numbered files whose names contain
// SHA-256 hashes of their exact bytes. Each publication syncs a private staging
// file, atomically renames it without replacement, and syncs the directory.
// Open validates all published records, including their sequence and run/input
// identity, and recovers the last complete checkpoint. Only recognized,
// unpublished staging files are discarded after successful validation; a bad
// published record never causes fallback to an older checkpoint. A write error
// may have occurred after publication: Close and Open again to establish the
// durable state, rather than assuming the write did not happen.
//
// Open has no expected-input parameter. Before resuming, the caller must compare
// Load().InputDigest with the intended input's canonical sha256:<lowercase hex>
// digest. Hashes detect corruption, not tampering by the owning user, and are
// not attestations. Data and artifacts remain private on disk, not encrypted;
// neither their contents nor caller-supplied paths or values appear in errors.
package journal
