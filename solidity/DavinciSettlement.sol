// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.24;

import {IZiskVerifier} from "./IZiskVerifier.sol";

/// @title DAVINCI per-batch settlement
/// @notice Reference on-chain settlement contract for one DAVINCI voting
///         batch. Takes the PLONK proof the ZisK prover emits, applies the
///         batch to the tracked process state, and re-verifies the KZG
///         opening of every DA blob the batch commits to.
///
/// publicValues (512 bytes = 64 registers × 8 LE bytes; the guest writes u32,
/// so the upper 4 bytes of each word are always zero):
///
///   [ 0]       ok                     (must be 1)
///   [ 1]       fail_mask              (must be 0)
///   [ 2.. 9]   root_before            (256-bit; reg32(2))
///   [10..17]   root_after             (256-bit; reg32(10))
///   [18]       voters
///   [19]       overwrites
///   [20..27]   census_root            (256-bit; reg32(20))
///   [28..35]   blobs_digest           (256-bit; reg32(28))
///   [36]       n_blobs
///   [42]       occupied_before
///
/// `reg32(k)` is the concatenation, for j = 0..7, of the low 4 bytes of
/// word k+j in little-endian order — i.e. `publicValues[8*(k+j) .. 8*(k+j)+4]`.
contract DavinciSettlement {
    // BLS12-381 scalar-field modulus (KZG point-evaluation precompile spec).
    uint256 internal constant BLS_MODULUS =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;

    // EIP-4844 point-evaluation precompile.
    address internal constant KZG_PRECOMPILE = address(0x0A);

    // Fixed field-element count the precompile echoes on success.
    uint256 internal constant KZG_FIELD_ELEMENTS = 4096;

    struct Process {
        bytes32 stateRoot;
        bytes32 censusRoot;
        uint64 voteCount;
        uint64 overwrittenCount;
        bool exists;
    }

    IZiskVerifier public immutable zisk;
    bytes32 public immutable programVK;
    bytes32 public immutable rootCVadcopFinal;

    mapping(bytes32 => Process) public processes;

    event ProcessCreated(bytes32 indexed processId, bytes32 genesisRoot, bytes32 censusRoot);
    event TransitionSettled(
        bytes32 indexed processId,
        bytes32 rootBefore,
        bytes32 rootAfter,
        uint64 voters,
        uint64 overwrites,
        uint64 nBlobs
    );

    error ProcessExists();
    error ProcessMissing();
    error PublicValuesLength();
    error CircuitFailed();
    error StateRootMismatch();
    error CensusRootMismatch();
    error OccupiedBeforeMismatch();
    error BlobsDigestMismatch();
    error BlobCountMismatch();
    error BadCommitmentLength();
    error BadProofLength();
    error MissingBlob();
    error KzgVerifyFailed();
    error KzgOutputMismatch();
    error NoBlobs();

    constructor(IZiskVerifier _zisk, bytes32 _programVK, bytes32 _rootCVadcopFinal) {
        zisk = _zisk;
        programVK = _programVK;
        rootCVadcopFinal = _rootCVadcopFinal;
    }

    /// @notice Register a new process. Reference implementation — no access
    ///         control; production deployments should gate this.
    function createProcess(bytes32 processId, bytes32 genesisRoot, bytes32 censusRoot) external {
        if (processes[processId].exists) revert ProcessExists();
        processes[processId] = Process({
            stateRoot: genesisRoot,
            censusRoot: censusRoot,
            voteCount: 0,
            overwrittenCount: 0,
            exists: true
        });
        emit ProcessCreated(processId, genesisRoot, censusRoot);
    }

    /// @notice Apply one batch to `processId`.
    /// @dev Must be sent as a blob transaction: `n_blobs` blob hashes are
    ///      read via `BLOBHASH`, one per commitment in `commitments`, in
    ///      the same order the guest published them.
    function submitTransition(
        bytes32 processId,
        bytes calldata publicValues,
        bytes calldata proofBytes,
        bytes[] calldata commitments,
        bytes32[] calldata ys,
        bytes[] calldata kzgProofs
    ) external {
        // 1. Verify the PLONK proof binds these public values.
        zisk.verifySnarkProof(programVK, rootCVadcopFinal, publicValues, proofBytes);

        // 2. Layout sanity.
        if (publicValues.length != 512) revert PublicValuesLength();

        // 3. ok / fail_mask.
        if (_word(publicValues, 0) != 1) revert CircuitFailed();
        if (_word(publicValues, 1) != 0) revert CircuitFailed();

        // 4. Check the process state matches publics, plus blob count + digest.
        _checkProcessAndDigest(processId, publicValues, commitments, ys, kzgProofs);

        // 5. Verify every blob's KZG opening.
        _verifyAllOpenings(processId, publicValues, commitments, ys, kzgProofs);

        // 6. Commit the transition and emit.
        Process storage p = processes[processId];
        p.stateRoot = _reg32(publicValues, 10);
        p.voteCount += uint64(_word(publicValues, 18));
        p.overwrittenCount += uint64(_word(publicValues, 19));

        emit TransitionSettled(
            processId,
            _reg32(publicValues, 2),
            _reg32(publicValues, 10),
            uint64(_word(publicValues, 18)),
            uint64(_word(publicValues, 19)),
            uint64(_word(publicValues, 36))
        );
    }

    function _checkProcessAndDigest(
        bytes32 processId,
        bytes calldata publicValues,
        bytes[] calldata commitments,
        bytes32[] calldata ys,
        bytes[] calldata kzgProofs
    ) internal view {
        Process storage p = processes[processId];
        if (!p.exists) revert ProcessMissing();

        if (_reg32(publicValues, 2) != p.stateRoot) revert StateRootMismatch();
        if (_reg32(publicValues, 20) != p.censusRoot) revert CensusRootMismatch();
        if (_word(publicValues, 42) != p.voteCount - p.overwrittenCount) revert OccupiedBeforeMismatch();

        uint256 n = _word(publicValues, 36);
        if (n < 1) revert NoBlobs();
        if (n != commitments.length || n != ys.length || n != kzgProofs.length) revert BlobCountMismatch();

        bytes memory buf;
        for (uint256 i = 0; i < n; i++) {
            if (commitments[i].length != 48) revert BadCommitmentLength();
            if (kzgProofs[i].length != 48) revert BadProofLength();
            buf = abi.encodePacked(buf, commitments[i], ys[i]);
        }
        if (sha256(buf) != _reg32(publicValues, 28)) revert BlobsDigestMismatch();
    }

    function _verifyAllOpenings(
        bytes32 processId,
        bytes calldata publicValues,
        bytes[] calldata commitments,
        bytes32[] calldata ys,
        bytes[] calldata kzgProofs
    ) internal view {
        bytes32 rootBeforeBE = _reverseBytes32(_reg32(publicValues, 2));
        uint256 n = _word(publicValues, 36);
        for (uint256 i = 0; i < n; i++) {
            _verifyOneOpening(processId, rootBeforeBE, commitments[i], ys[i], kzgProofs[i], i);
        }
    }

    function _verifyOneOpening(
        bytes32 processId,
        bytes32 rootBeforeBE,
        bytes calldata commitment,
        bytes32 y,
        bytes calldata kzgProof,
        uint256 idx
    ) internal view {
        bytes32 vh = blobhash(idx);
        if (vh == bytes32(0)) revert MissingBlob();

        bytes32 z = bytes32(
            uint256(sha256(abi.encodePacked(processId, rootBeforeBE, commitment))) % BLS_MODULUS
        );
        bytes memory input = abi.encodePacked(vh, z, y, commitment, kzgProof);
        (bool ok, bytes memory out) = KZG_PRECOMPILE.staticcall(input);
        if (!ok) revert KzgVerifyFailed();
        if (out.length != 64) revert KzgOutputMismatch();
        bytes memory expected = abi.encode(uint256(KZG_FIELD_ELEMENTS), BLS_MODULUS);
        if (keccak256(out) != keccak256(expected)) revert KzgOutputMismatch();
    }

    // --- helpers -----------------------------------------------------------

    /// @dev Read the 8-byte little-endian word at offset `8*k`.
    function _word(bytes calldata pv, uint256 k) internal pure returns (uint64 w) {
        uint256 off = 8 * k;
        for (uint256 i = 0; i < 8; i++) {
            w |= uint64(uint8(pv[off + i])) << uint64(8 * i);
        }
    }

    /// @dev Concatenate the low 4 bytes of words k..k+7 in LE order into bytes32.
    function _reg32(bytes calldata pv, uint256 k) internal pure returns (bytes32 out) {
        // Assemble the 32 bytes directly in a uint256 to avoid a memory alloc.
        uint256 acc;
        for (uint256 j = 0; j < 8; j++) {
            uint256 src = 8 * (k + j);
            // byte(4j+t) = pv[src+t]. bytes32 stores byte 0 in the top of the word,
            // so the top-most byte we're writing goes at bit-shift 8 * (31 - (4j+t)).
            for (uint256 t = 0; t < 4; t++) {
                acc |= uint256(uint8(pv[src + t])) << (8 * (31 - (4 * j + t)));
            }
        }
        out = bytes32(acc);
    }

    /// @dev Reverse the byte order of a bytes32.
    function _reverseBytes32(bytes32 x) internal pure returns (bytes32 out) {
        uint256 acc;
        for (uint256 i = 0; i < 32; i++) {
            uint256 b = uint8(x[i]);
            acc |= b << (8 * i);
        }
        out = bytes32(acc);
    }
}
