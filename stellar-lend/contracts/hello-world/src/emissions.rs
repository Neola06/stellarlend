//! # Retroactive Emissions Claim with Merkle Proof Root Rotation
//!
//! This module implements a system for users to claim retroactive emissions
//! (rewards) using Merkle proofs. It supports Merkle root rotation to allow
//! updating the emissions distribution without requiring users to re-submit
//! claims.
//!
//! ## Features
//! - Merkle proof verification for emissions claims
//! - Merkle root rotation with timelock for governance safety
//! - Claim tracking to prevent double-claiming
//! - Batch claim support for gas efficiency
//! - Emissions vesting schedules
//!
//! ## Security
//! - Proof verification uses constant-time comparison
//! - Root rotation requires governance proposal
//! - Claims are tracked per-user per-epoch
//! - Emergency pause by guardians

#![allow(unused)]

use soroban_sdk::{
    contracterror, contractevent, contracttype, Address, Env, Map, String, Symbol, Vec, BytesN,
};

use crate::errors::LendingError;
use crate::governance::state::{get_config as get_gov_config, get_admin};
use crate::governance::types::ProposalType;
use crate::pause::is_paused;
use crate::traits::AdminTrait;

/// Maximum depth of the Merkle tree (supports up to 2^20 leaves)
const MAX_MERKLE_DEPTH: u32 = 20;

/// Maximum number of claims per batch
const MAX_BATCH_CLAIMS: u32 = 50;

/// Maximum number of roots to keep in history
const MAX_ROOT_HISTORY: u32 = 10;

/// Events for emissions operations
#[contractevent]
#[derive(Clone, Debug)]
pub struct EmissionsMerkleRootUpdatedEvent {
    pub epoch: u64,
    pub old_root: BytesN<32>,
    pub new_root: BytesN<32>,
    pub rotated_by: Address,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct EmissionsClaimedEvent {
    pub user: Address,
    pub epoch: u64,
    pub amount: i128,
    pub token: Address,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct EmissionsBatchClaimedEvent {
    pub user: Address,
    pub epoch: u64,
    pub total_amount: i128,
    pub claim_count: u32,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct EmissionsVestingScheduledEvent {
    pub user: Address,
    pub epoch: u64,
    pub amount: i128,
    pub vesting_start: u64,
    pub vesting_end: u64,
    pub timestamp: u64,
}

/// Errors that can occur during emissions operations
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EmissionsError {
    /// Merkle proof verification failed
    InvalidProof = 1,
    /// Merkle root not found for epoch
    RootNotFound = 2,
    /// Claim already made for this epoch
    AlreadyClaimed = 3,
    /// Invalid epoch (too old or future)
    InvalidEpoch = 4,
    /// Amount exceeds allocation
    ExceedsAllocation = 5,
    /// Zero amount claim
    ZeroAmount = 6,
    /// Batch size exceeds limit
    BatchTooLarge = 7,
    /// Root rotation not authorized
    UnauthorizedRotation = 8,
    /// Timelock not elapsed for root rotation
    TimelockNotElapsed = 9,
    /// Emissions paused
    Paused = 10,
    /// Invalid vesting schedule
    InvalidVesting = 11,
    /// Arithmetic overflow
    Overflow = 12,
    /// Token not configured
    TokenNotConfigured = 13,
}

/// Storage keys for emissions data
#[contracttype]
#[derive(Clone)]
pub enum EmissionsDataKey {
    /// Current Merkle root for an epoch: MerkleRoot(epoch) -> MerkleRootData
    MerkleRoot(u64),
    /// Pending root rotation: PendingRoot(epoch) -> PendingRootData
    PendingRoot(u64),
    /// User claim tracking: UserClaim(user, epoch) -> ClaimData
    UserClaim(Address, u64),
    /// Emissions token per epoch: EmissionsToken(epoch) -> Address
    EmissionsToken(u64),
    /// Total emissions per epoch: TotalEmissions(epoch) -> i128
    TotalEmissions(u64),
    /// Vesting schedules: VestingSchedule(user, epoch) -> VestingData
    VestingSchedule(Address, u64),
    /// Global config: EmissionsConfig -> EmissionsConfigData
    EmissionsConfig,
    /// Root history for verification: RootHistory(index) -> BytesN<32>
    RootHistory(u32),
    /// Next root history index: NextRootHistoryIndex -> u32
    NextRootHistoryIndex,
}

/// Merkle root data for an epoch
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleRootData {
    pub root: BytesN<32>,
    pub epoch: u64,
    pub total_allocation: i128,
    pub token: Address,
    pub created_at: u64,
    pub is_active: bool,
}

/// Pending root rotation data
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRootData {
    pub new_root: BytesN<32>,
    pub proposed_by: Address,
    pub proposed_at: u64,
    pub execution_time: u64,
}

/// User claim data
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimData {
    pub user: Address,
    pub epoch: u64,
    pub amount_claimed: i128,
    pub claimed_at: u64,
    pub proof_hash: BytesN<32>, // Hash of the proof used for audit
}

/// Vesting schedule data
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VestingData {
    pub user: Address,
    pub epoch: u64,
    pub total_amount: i128,
    pub claimed_amount: i128,
    pub vesting_start: u64,
    pub vesting_end: u64,
    pub last_claim_time: u64,
}

/// Global emissions configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmissionsConfigData {
    pub admin: Address,
    pub rotation_timelock: u64, // Seconds before pending root can be executed
    pub max_epochs_to_keep: u64,
    pub default_vesting_period: u64, // Seconds
    pub paused: bool,
}

/// Merkle proof structure
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: BytesN<32>,
    pub path: Vec<BytesN<32>>,
    pub path_indices: Vec<bool>, // true = right, false = left
}

/// Claim input for single claim
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimInput {
    pub epoch: u64,
    pub proof: MerkleProof,
    pub amount: i128,
}

/// Claim input for batch claim
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchClaimInput {
    pub epoch: u64,
    pub claims: Vec<MerkleProof>,
    pub amounts: Vec<i128>,
}

/// Initialize emissions module
///
/// # Arguments
/// * `env` - The contract environment
/// * `admin` - Admin address (must authorize)
/// * `rotation_timelock` - Timelock for root rotation in seconds
/// * `default_vesting_period` - Default vesting period in seconds
///
/// # Errors
/// * `Unauthorized` - Caller is not admin
pub fn initialize_emissions(
    env: &Env,
    admin: Address,
    rotation_timelock: u64,
    default_vesting_period: u64,
) -> Result<(), EmissionsError> {
    admin.require_auth();

    // Verify caller is governance admin
    let stored_admin = get_admin(env).map_err(|_| EmissionsError::UnauthorizedRotation)?;
    if admin != stored_admin {
        return Err(EmissionsError::UnauthorizedRotation);
    }

    let config = EmissionsConfigData {
        admin: admin.clone(),
        rotation_timelock,
        max_epochs_to_keep: 100,
        default_vesting_period,
        paused: false,
    };

    env.storage()
        .instance()
        .set(&EmissionsDataKey::EmissionsConfig, &config);

    // Initialize root history index
    env.storage()
        .instance()
        .set(&EmissionsDataKey::NextRootHistoryIndex, &0u32);

    Ok(())
}

/// Set Merkle root for an epoch (initial setup or governance rotation)
///
/// # Arguments
/// * `env` - The contract environment
/// * `caller` - Caller address (must be admin or governance)
/// * `epoch` - Epoch number
/// * `root` - Merkle root (32 bytes)
/// * `total_allocation` - Total emissions allocation for this epoch
/// * `token` - Token address for emissions
///
/// # Errors
/// * `UnauthorizedRotation` - Caller not authorized
/// * `InvalidEpoch` - Epoch is invalid
pub fn set_merkle_root(
    env: &Env,
    caller: Address,
    epoch: u64,
    root: BytesN<32>,
    total_allocation: i128,
    token: Address,
) -> Result<(), EmissionsError> {
    let config = get_emissions_config(env)?;

    // Check authorization
    if caller != config.admin {
        // Check if caller is governance via proposal execution
        // This would be called by the governance execute_proposal
        // For now, only admin can set directly
        return Err(EmissionsError::UnauthorizedRotation);
    }

    if total_allocation <= 0 {
        return Err(EmissionsError::ZeroAmount);
    }

    let current_time = env.ledger().timestamp();

    let root_data = MerkleRootData {
        root: root.clone(),
        epoch,
        total_allocation,
        token: token.clone(),
        created_at: current_time,
        is_active: true,
    };

    // Store root
    env.storage()
        .persistent()
        .set(&EmissionsDataKey::MerkleRoot(epoch), &root_data);

    // Store token and total emissions for epoch
    env.storage()
        .persistent()
        .set(&EmissionsDataKey::EmissionsToken(epoch), &token);
    env.storage()
        .persistent()
        .set(&EmissionsDataKey::TotalEmissions(epoch), &total_allocation);

    // Add to root history
    add_to_root_history(env, root)?;

    // Deactivate old roots for this epoch if any
    deactivate_old_roots(env, epoch)?;

    Ok(())
}

/// Propose a new Merkle root for an epoch (governance rotation)
///
/// # Arguments
/// * `env` - The contract environment
/// * `proposer` - Proposer address (must be admin or have governance power)
/// * `epoch` - Epoch number
/// * `new_root` - New Merkle root
///
/// # Errors
/// * `UnauthorizedRotation` - Caller not authorized
/// * `RootNotFound` - No existing root for epoch
/// * `InvalidEpoch` - Epoch is invalid
pub fn propose_root_rotation(
    env: &Env,
    proposer: Address,
    epoch: u64,
    new_root: BytesN<32>,
) -> Result<(), EmissionsError> {
    let config = get_emissions_config(env)?;

    // Check if paused
    if config.paused {
        return Err(EmissionsError::Paused);
    }

    // Verify proposer is admin or has governance power
    if proposer != config.admin {
        let gov_config = get_gov_config(env).map_err(|_| EmissionsError::UnauthorizedRotation)?;
        let proposer_votes = crate::governance::power::get_past_votes(env, &proposer, env.ledger().timestamp());
        if proposer_votes < gov_config.proposal_threshold {
            return Err(EmissionsError::UnauthorizedRotation);
        }
    }

    // Check existing root exists
    let existing_root: MerkleRootData = env
        .storage()
        .persistent()
        .get(&EmissionsDataKey::MerkleRoot(epoch))
        .ok_or(EmissionsError::RootNotFound)?;

    if !existing_root.is_active {
        return Err(EmissionsError::RootNotFound);
    }

    let current_time = env.ledger().timestamp();
    let execution_time = current_time + config.rotation_timelock;

    let pending = PendingRootData {
        new_root: new_root.clone(),
        proposed_by: proposer.clone(),
        proposed_at: current_time,
        execution_time,
    };

    env.storage()
        .persistent()
        .set(&EmissionsDataKey::PendingRoot(epoch), &pending);

    Ok(())
}

/// Execute a pending root rotation
///
/// # Arguments
/// * `env` - The contract environment
/// * `executor` - Executor address
/// * `epoch` - Epoch number
///
/// # Errors
/// * `TimelockNotElapsed` - Timelock not yet elapsed
/// * `RootNotFound` - No pending root for epoch
pub fn execute_root_rotation(
    env: &Env,
    executor: Address,
    epoch: u64,
) -> Result<(), EmissionsError> {
    let config = get_emissions_config(env)?;
    let current_time = env.ledger().timestamp();

    // Get pending root
    let pending: PendingRootData = env
        .storage()
        .persistent()
        .get(&EmissionsDataKey::PendingRoot(epoch))
        .ok_or(EmissionsError::RootNotFound)?;

    // Check timelock
    if current_time < pending.execution_time {
        return Err(EmissionsError::TimelockNotElapsed);
    }

    // Get old root
    let old_root_data: MerkleRootData = env
        .storage()
        .persistent()
        .get(&EmissionsDataKey::MerkleRoot(epoch))
        .ok_or(EmissionsError::RootNotFound)?;

    let old_root = old_root_data.root.clone();

    // Update root data
    let mut updated_root = old_root_data;
    updated_root.root = pending.new_root.clone();
    updated_root.created_at = current_time;

    env.storage()
        .persistent()
        .set(&EmissionsDataKey::MerkleRoot(epoch), &updated_root);

    // Add new root to history
    add_to_root_history(env, pending.new_root.clone())?;

    // Remove pending
    env.storage()
        .persistent()
        .remove(&EmissionsDataKey::PendingRoot(epoch));

    // Emit event
    EmissionsMerkleRootUpdatedEvent {
        epoch,
        old_root,
        new_root: pending.new_root,
        rotated_by: executor,
        timestamp: current_time,
    }
    .publish(env);

    Ok(())
}

/// Claim emissions for a single epoch using Merkle proof
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - User address (must authorize)
/// * `input` - Claim input with epoch, proof, and amount
///
/// # Errors
/// * `InvalidProof` - Merkle proof verification failed
/// * `AlreadyClaimed` - User already claimed for this epoch
/// * `RootNotFound` - No root for epoch
/// * `ExceedsAllocation` - Amount exceeds allocation
/// * `ZeroAmount` - Amount is zero
pub fn claim_emissions(
    env: &Env,
    user: Address,
    input: ClaimInput,
) -> Result<i128, EmissionsError> {
    user.require_auth();

    let config = get_emissions_config(env)?;

    if config.paused {
        return Err(EmissionsError::Paused);
    }

    if input.amount <= 0 {
        return Err(EmissionsError::ZeroAmount);
    }

    // Check if already claimed
    let claim_key = EmissionsDataKey::UserClaim(user.clone(), input.epoch);
    if env.storage().persistent().has(&claim_key) {
        return Err(EmissionsError::AlreadyClaimed);
    }

    // Get root for epoch
    let root_data: MerkleRootData = env
        .storage()
        .persistent()
        .get(&EmissionsDataKey::MerkleRoot(input.epoch))
        .ok_or(EmissionsError::RootNotFound)?;

    if !root_data.is_active {
        return Err(EmissionsError::RootNotFound);
    }

    // Verify Merkle proof
    verify_merkle_proof(env, &root_data.root, &input.proof)?;

    // Check allocation
    if input.amount > root_data.total_allocation {
        return Err(EmissionsError::ExceedsAllocation);
    }

    // Check vesting if applicable
    let vesting_key = EmissionsDataKey::VestingSchedule(user.clone(), input.epoch);
    let vesting: Option<VestingData> = env.storage().persistent().get(&vesting_key);

    let claimable_amount = if let Some(v) = vesting {
        calculate_vested_amount(&v, env.ledger().timestamp())
    } else {
        input.amount
    };

    if claimable_amount <= 0 {
        return Err(EmissionsError::ZeroAmount);
    }

    // Record claim
    let proof_hash = hash_proof(env, &input.proof);
    let claim_data = ClaimData {
        user: user.clone(),
        epoch: input.epoch,
        amount_claimed: claimable_amount,
        claimed_at: env.ledger().timestamp(),
        proof_hash,
    };

    env.storage().persistent().set(&claim_key, &claim_data);

    // Update vesting if exists
    if let Some(mut v) = vesting {
        v.claimed_amount = v.claimed_amount.saturating_add(claimable_amount);
        v.last_claim_time = env.ledger().timestamp();
        env.storage().persistent().set(&vesting_key, &v);
    }

    // Transfer tokens
    transfer_emissions_token(env, &root_data.token, &user, claimable_amount)?;

    // Emit event
    EmissionsClaimedEvent {
        user: user.clone(),
        epoch: input.epoch,
        amount: claimable_amount,
        token: root_data.token.clone(),
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(claimable_amount)
}

/// Batch claim emissions for multiple proofs in same epoch
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - User address (must authorize)
/// * `input` - Batch claim input
///
/// # Errors
/// * `BatchTooLarge` - Too many claims in batch
/// * `InvalidProof` - Any proof verification failed
/// * `AlreadyClaimed` - User already claimed for this epoch
pub fn batch_claim_emissions(
    env: &Env,
    user: Address,
    input: BatchClaimInput,
) -> Result<i128, EmissionsError> {
    user.require_auth();

    let config = get_emissions_config(env)?;

    if config.paused {
        return Err(EmissionsError::Paused);
    }

    let claim_count = input.claims.len() as u32;
    if claim_count == 0 || claim_count > MAX_BATCH_CLAIMS {
        return Err(EmissionsError::BatchTooLarge);
    }

    if input.amounts.len() != claim_count as usize {
        return Err(EmissionsError::InvalidProof);
    }

    // Check if already claimed for this epoch
    let claim_key = EmissionsDataKey::UserClaim(user.clone(), input.epoch);
    if env.storage().persistent().has(&claim_key) {
        return Err(EmissionsError::AlreadyClaimed);
    }

    // Get root for epoch
    let root_data: MerkleRootData = env
        .storage()
        .persistent()
        .get(&EmissionsDataKey::MerkleRoot(input.epoch))
        .ok_or(EmissionsError::RootNotFound)?;

    if !root_data.is_active {
        return Err(EmissionsError::RootNotFound);
    }

    let mut total_claimed = 0i128;

    // Verify all proofs and calculate total
    for i in 0..claim_count as usize {
        let proof = input.claims.get(i).unwrap();
        let amount = input.amounts.get(i).unwrap();

        if amount <= 0 {
            return Err(EmissionsError::ZeroAmount);
        }

        verify_merkle_proof(env, &root_data.root, &proof)?;

        total_claimed = total_claimed
            .checked_add(amount)
            .ok_or(EmissionsError::Overflow)?;
    }

    if total_claimed > root_data.total_allocation {
        return Err(EmissionsError::ExceedsAllocation);
    }

    // Check vesting
    let vesting_key = EmissionsDataKey::VestingSchedule(user.clone(), input.epoch);
    let vesting: Option<VestingData> = env.storage().persistent().get(&vesting_key);

    let claimable_amount = if let Some(v) = vesting {
        calculate_vested_amount(&v, env.ledger().timestamp())
    } else {
        total_claimed
    };

    if claimable_amount <= 0 {
        return Err(EmissionsError::ZeroAmount);
    }

    // Record claim (using first proof hash for audit)
    let proof_hash = hash_proof(env, &input.claims.get(0).unwrap());
    let claim_data = ClaimData {
        user: user.clone(),
        epoch: input.epoch,
        amount_claimed: claimable_amount,
        claimed_at: env.ledger().timestamp(),
        proof_hash,
    };

    env.storage().persistent().set(&claim_key, &claim_data);

    // Update vesting if exists
    if let Some(mut v) = vesting {
        v.claimed_amount = v.claimed_amount.saturating_add(claimable_amount);
        v.last_claim_time = env.ledger().timestamp();
        env.storage().persistent().set(&vesting_key, &v);
    }

    // Transfer tokens
    transfer_emissions_token(env, &root_data.token, &user, claimable_amount)?;

    // Emit event
    EmissionsBatchClaimedEvent {
        user: user.clone(),
        epoch: input.epoch,
        total_amount: claimable_amount,
        claim_count,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(claimable_amount)
}

/// Schedule vesting for emissions claim
///
/// # Arguments
/// * `env` - The contract environment
/// * `admin` - Admin address (must authorize)
/// * `user` - User address
/// * `epoch` - Epoch number
/// * `amount` - Total amount to vest
/// * `vesting_start` - Vesting start timestamp
/// * `vesting_end` - Vesting end timestamp
///
/// # Errors
/// * `UnauthorizedRotation` - Caller not admin
/// * `InvalidVesting` - Invalid vesting parameters
pub fn schedule_vesting(
    env: &Env,
    admin: Address,
    user: Address,
    epoch: u64,
    amount: i128,
    vesting_start: u64,
    vesting_end: u64,
) -> Result<(), EmissionsError> {
    admin.require_auth();

    let config = get_emissions_config(env)?;
    if admin != config.admin {
        return Err(EmissionsError::UnauthorizedRotation);
    }

    if amount <= 0 {
        return Err(EmissionsError::ZeroAmount);
    }

    if vesting_end <= vesting_start {
        return Err(EmissionsError::InvalidVesting);
    }

    if vesting_start < env.ledger().timestamp() {
        return Err(EmissionsError::InvalidVesting);
    }

    // Verify epoch has root
    let _root_data: MerkleRootData = env
        .storage()
        .persistent()
        .get(&EmissionsDataKey::MerkleRoot(epoch))
        .ok_or(EmissionsError::RootNotFound)?;

    let vesting = VestingData {
        user: user.clone(),
        epoch,
        total_amount: amount,
        claimed_amount: 0,
        vesting_start,
        vesting_end,
        last_claim_time: 0,
    };

    env.storage()
        .persistent()
        .set(&EmissionsDataKey::VestingSchedule(user, epoch), &vesting);

    EmissionsVestingScheduledEvent {
        user,
        epoch,
        amount,
        vesting_start,
        vesting_end,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(())
}

/// Get claim data for a user and epoch
pub fn get_user_claim(env: &Env, user: Address, epoch: u64) -> Option<ClaimData> {
    env.storage()
        .persistent()
        .get(&EmissionsDataKey::UserClaim(user, epoch))
}

/// Get vesting schedule for a user and epoch
pub fn get_vesting_schedule(env: &Env, user: Address, epoch: u64) -> Option<VestingData> {
    env.storage()
        .persistent()
        .get(&EmissionsDataKey::VestingSchedule(user, epoch))
}

/// Get Merkle root data for an epoch
pub fn get_merkle_root_data(env: &Env, epoch: u64) -> Option<MerkleRootData> {
    env.storage()
        .persistent()
        .get(&EmissionsDataKey::MerkleRoot(epoch))
}

/// Get pending root rotation for an epoch
pub fn get_pending_root(env: &Env, epoch: u64) -> Option<PendingRootData> {
    env.storage()
        .persistent()
        .get(&EmissionsDataKey::PendingRoot(epoch))
}

/// Get emissions config
pub fn get_emissions_config(env: &Env) -> Result<EmissionsConfigData, EmissionsError> {
    env.storage()
        .instance()
        .get(&EmissionsDataKey::EmissionsConfig)
        .ok_or(EmissionsError::RootNotFound)
}

/// Set emissions pause (admin only)
pub fn set_emissions_pause(env: &Env, admin: Address, paused: bool) -> Result<(), EmissionsError> {
    admin.require_auth();

    let mut config = get_emissions_config(env)?;
    if admin != config.admin {
        return Err(EmissionsError::UnauthorizedRotation);
    }

    config.paused = paused;
    env.storage()
        .instance()
        .set(&EmissionsDataKey::EmissionsConfig, &config);

    Ok(())
}

// Internal helper functions

/// Verify a Merkle proof against a root
fn verify_merkle_proof(
    env: &Env,
    root: &BytesN<32>,
    proof: &MerkleProof,
) -> Result<(), EmissionsError> {
    // Validate path length
    if proof.path.len() > MAX_MERKLE_DEPTH {
        return Err(EmissionsError::InvalidProof);
    }

    if proof.path.len() != proof.path_indices.len() {
        return Err(EmissionsError::InvalidProof);
    }

    // Compute root from leaf and path
    let mut current_hash = proof.leaf.clone();

    for i in 0..proof.path.len() {
        let sibling = proof.path.get(i).unwrap();
        let is_right = proof.path_indices.get(i).unwrap();

        current_hash = if is_right {
            hash_pair(env, &current_hash, sibling)
        } else {
            hash_pair(env, sibling, &current_hash)
        };
    }

    // Constant-time comparison
    if !bytes_equal(&current_hash, root) {
        return Err(EmissionsError::InvalidProof);
    }

    Ok(())
}

/// Hash a pair of 32-byte values
fn hash_pair(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut combined = Vec::new(env);
    combined.append(&left.to_vec());
    combined.append(&right.to_vec());
    env.crypto().sha256(&combined).into()
}

/// Hash a proof for audit trail
fn hash_proof(env: &Env, proof: &MerkleProof) -> BytesN<32> {
    let mut data = Vec::new(env);
    data.append(&proof.leaf.to_vec());
    for sibling in proof.path.iter() {
        data.append(&sibling.to_vec());
    }
    for &idx in proof.path_indices.iter() {
        data.push_back(if idx { 1u8 } else { 0u8 });
    }
    env.crypto().sha256(&data).into()
}

/// Constant-time byte comparison
fn bytes_equal(a: &BytesN<32>, b: &BytesN<32>) -> bool {
    let a_bytes = a.to_array();
    let b_bytes = b.to_array();
    let mut result = 0u8;
    for i in 0..32 {
        result |= a_bytes[i] ^ b_bytes[i];
    }
    result == 0
}

/// Add root to history
fn add_to_root_history(env: &Env, root: BytesN<32>) -> Result<(), EmissionsError> {
    let mut index: u32 = env
        .storage()
        .instance()
        .get(&EmissionsDataKey::NextRootHistoryIndex)
        .unwrap_or(0);

    env.storage()
        .persistent()
        .set(&EmissionsDataKey::RootHistory(index), &root);

    index = index.saturating_add(1);
    if index >= MAX_ROOT_HISTORY {
        index = 0; // Circular buffer
    }

    env.storage()
        .instance()
        .set(&EmissionsDataKey::NextRootHistoryIndex, &index);

    Ok(())
}

/// Deactivate old roots for an epoch (keep only latest)
fn deactivate_old_roots(env: &Env, epoch: u64) -> Result<(), EmissionsError> {
    // In this implementation, we only keep one active root per epoch
    // The new root replaces the old one via set_merkle_root or execute_root_rotation
    Ok(())
}

/// Calculate vested amount based on time elapsed
fn calculate_vested_amount(vesting: &VestingData, current_time: u64) -> i128 {
    if current_time < vesting.vesting_start {
        return 0;
    }

    if current_time >= vesting.vesting_end {
        return vesting.total_amount.saturating_sub(vesting.claimed_amount);
    }

    // Linear vesting
    let total_duration = vesting.vesting_end.saturating_sub(vesting.vesting_start);
    let elapsed = current_time.saturating_sub(vesting.vesting_start);

    let vested_total = (vesting.total_amount * elapsed as i128) / total_duration as i128;
    vested_total.saturating_sub(vesting.claimed_amount)
}

/// Transfer emissions token to user
fn transfer_emissions_token(
    env: &Env,
    token: &Address,
    to: &Address,
    amount: i128,
) -> Result<(), EmissionsError> {
    let token_client = soroban_sdk::token::Client::new(env, token);
    token_client.transfer(&env.current_contract_address(), to, &amount);
    Ok(())
}

/// Claim vested emissions (for ongoing vesting claims)
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - User address (must authorize)
/// * `epoch` - Epoch number
///
/// # Errors
/// * `InvalidVesting` - No vesting schedule or nothing to claim
/// * `RootNotFound` - No root for epoch
pub fn claim_vested_emissions(
    env: &Env,
    user: Address,
    epoch: u64,
) -> Result<i128, EmissionsError> {
    user.require_auth();

    let config = get_emissions_config(env)?;

    if config.paused {
        return Err(EmissionsError::Paused);
    }

    // Get vesting schedule
    let vesting_key = EmissionsDataKey::VestingSchedule(user.clone(), epoch);
    let mut vesting: VestingData = env
        .storage()
        .persistent()
        .get(&vesting_key)
        .ok_or(EmissionsError::InvalidVesting)?;

    // Calculate claimable amount
    let claimable = calculate_vested_amount(&vesting, env.ledger().timestamp());

    if claimable <= 0 {
        return Err(EmissionsError::ZeroAmount);
    }

    // Get root data for token
    let root_data: MerkleRootData = env
        .storage()
        .persistent()
        .get(&EmissionsDataKey::MerkleRoot(epoch))
        .ok_or(EmissionsError::RootNotFound)?;

    // Update vesting
    vesting.claimed_amount = vesting.claimed_amount.saturating_add(claimable);
    vesting.last_claim_time = env.ledger().timestamp();
    env.storage().persistent().set(&vesting_key, &vesting);

    // Transfer tokens
    transfer_emissions_token(env, &root_data.token, &user, claimable)?;

    // Emit event
    EmissionsClaimedEvent {
        user: user.clone(),
        epoch,
        amount: claimable,
        token: root_data.token.clone(),
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(claimable)
}

// Contract client interface for external calls
#[cfg(feature = "client")]
pub mod client {
    use super::*;
    use soroban_sdk::contractclient;

    #[contractclient(name = "EmissionsClient")]
    pub trait EmissionsClientInterface {
        fn initialize_emissions(
            env: Env,
            admin: Address,
            rotation_timelock: u64,
            default_vesting_period: u64,
        ) -> Result<(), EmissionsError>;

        fn set_merkle_root(
            env: Env,
            caller: Address,
            epoch: u64,
            root: BytesN<32>,
            total_allocation: i128,
            token: Address,
        ) -> Result<(), EmissionsError>;

        fn propose_root_rotation(
            env: Env,
            proposer: Address,
            epoch: u64,
            new_root: BytesN<32>,
        ) -> Result<(), EmissionsError>;

        fn execute_root_rotation(
            env: Env,
            executor: Address,
            epoch: u64,
        ) -> Result<(), EmissionsError>;

        fn claim_emissions(
            env: Env,
            user: Address,
            input: ClaimInput,
        ) -> Result<i128, EmissionsError>;

        fn batch_claim_emissions(
            env: Env,
            user: Address,
            input: BatchClaimInput,
        ) -> Result<i128, EmissionsError>;

        fn schedule_vesting(
            env: Env,
            admin: Address,
            user: Address,
            epoch: u64,
            amount: i128,
            vesting_start: u64,
            vesting_end: u64,
        ) -> Result<(), EmissionsError>;

        fn claim_vested_emissions(
            env: Env,
            user: Address,
            epoch: u64,
        ) -> Result<i128, EmissionsError>;

        fn set_emissions_pause(
            env: Env,
            admin: Address,
            paused: bool,
        ) -> Result<(), EmissionsError>;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        testutils::Address as _,
        Address, BytesN, Env, Vec,
    };

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        (env, admin, user)
    }

    fn create_test_proof(env: &Env, leaf: BytesN<32>) -> MerkleProof {
        // Create a simple proof with empty path (leaf == root)
        MerkleProof {
            leaf,
            path: Vec::new(env),
            path_indices: Vec::new(env),
        }
    }

    #[test]
    fn test_initialize_emissions() {
        let (env, admin, _user) = setup();
        initialize_emissions(&env, admin.clone(), 86400, 2592000).unwrap();

        let config = get_emissions_config(&env).unwrap();
        assert_eq!(config.admin, admin);
        assert_eq!(config.rotation_timelock, 86400);
        assert_eq!(config.default_vesting_period, 2592000);
        assert!(!config.paused);
    }

    #[test]
    fn test_set_merkle_root() {
        let (env, admin, _user) = setup();
        initialize_emissions(&env, admin.clone(), 86400, 2592000).unwrap();

        let epoch = 1u64;
        let root = BytesN::from_array(&env, &[1u8; 32]);
        let token = Address::generate(&env);
        let total_allocation = 1000000i128;

        set_merkle_root(&env, admin.clone(), epoch, root.clone(), total_allocation, token.clone())
            .unwrap();

        let root_data = get_merkle_root_data(&env, epoch).unwrap();
        assert_eq!(root_data.root, root);
        assert_eq!(root_data.epoch, epoch);
        assert_eq!(root_data.total_allocation, total_allocation);
        assert_eq!(root_data.token, token);
        assert!(root_data.is_active);
    }

    #[test]
    fn test_propose_and_execute_root_rotation() {
        let (env, admin, _user) = setup();
        initialize_emissions(&env, admin.clone(), 10, 2592000).unwrap(); // 10 second timelock

        let epoch = 1u64;
        let root1 = BytesN::from_array(&env, &[1u8; 32]);
        let root2 = BytesN::from_array(&env, &[2u8; 32]);
        let token = Address::generate(&env);

        set_merkle_root(&env, admin.clone(), epoch, root1.clone(), 1000000, token.clone())
            .unwrap();

        // Propose rotation
        propose_root_rotation(&env, admin.clone(), epoch, root2.clone()).unwrap();

        let pending = get_pending_root(&env, epoch).unwrap();
        assert_eq!(pending.new_root, root2);
        assert_eq!(pending.proposed_by, admin);

        // Try to execute before timelock - should fail
        let result = execute_root_rotation(&env, admin.clone(), epoch);
        assert!(result.is_err());

        // Advance time past timelock
        env.ledger().with_mut(|li| {
            li.timestamp = pending.execution_time + 1;
        });

        // Execute rotation
        execute_root_rotation(&env, admin.clone(), epoch).unwrap();

        let root_data = get_merkle_root_data(&env, epoch).unwrap();
        assert_eq!(root_data.root, root2);
        assert_eq!(root_data.created_at, pending.execution_time + 1);

        // Pending should be removed
        assert!(get_pending_root(&env, epoch).is_none());
    }

    #[test]
    fn test_claim_emissions() {
        let (env, admin, user) = setup();
        initialize_emissions(&env, admin.clone(), 86400, 2592000).unwrap();

        let epoch = 1u64;
        let leaf = BytesN::from_array(&env, &[42u8; 32]);
        let root = leaf.clone(); // Simple case: leaf == root
        let token = Address::generate(&env);
        let total_allocation = 1000000i128;

        set_merkle_root(&env, admin.clone(), epoch, root.clone(), total_allocation, token.clone())
            .unwrap();

        // Mint some tokens to contract for distribution
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.mint(&env.current_contract_address(), &total_allocation);

        let proof = create_test_proof(&env, leaf);
        let claim_amount = 500000i128;

        let claimed = claim_emissions(
            &env,
            user.clone(),
            ClaimInput {
                epoch,
                proof,
                amount: claim_amount,
            },
        ).unwrap();

        assert_eq!(claimed, claim_amount);

        // Try to claim again - should fail
        let result = claim_emissions(
            &env,
            user.clone(),
            ClaimInput {
                epoch,
                proof: create_test_proof(&env, leaf),
                amount: claim_amount,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_claim_emissions() {
        let (env, admin, user) = setup();
        initialize_emissions(&env, admin.clone(), 86400, 2592000).unwrap();

        let epoch = 1u64;
        let leaf1 = BytesN::from_array(&env, &[1u8; 32]);
        let leaf2 = BytesN::from_array(&env, &[2u8; 32]);
        let root = BytesN::from_array(&env, &[3u8; 32]); // Different root for testing
        let token = Address::generate(&env);
        let total_allocation = 1000000i128;

        set_merkle_root(&env, admin.clone(), epoch, root.clone(), total_allocation, token.clone())
            .unwrap();

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.mint(&env.current_contract_address(), &total_allocation);

        let mut claims = Vec::new(&env);
        let mut amounts = Vec::new(&env);
        claims.push_back(create_test_proof(&env, leaf1));
        claims.push_back(create_test_proof(&env, leaf2));
        amounts.push_back(300000i128);
        amounts.push_back(200000i128);

        let claimed = batch_claim_emissions(
            &env,
            user.clone(),
            BatchClaimInput {
                epoch,
                claims,
                amounts,
            },
        ).unwrap();

        assert_eq!(claimed, 500000i128);
    }

    #[test]
    fn test_schedule_and_claim_vesting() {
        let (env, admin, user) = setup();
        initialize_emissions(&env, admin.clone(), 86400, 2592000).unwrap();

        let epoch = 1u64;
        let leaf = BytesN::from_array(&env, &[42u8; 32]);
        let root = leaf.clone();
        let token = Address::generate(&env);
        let total_allocation = 1000000i128;

        set_merkle_root(&env, admin.clone(), epoch, root.clone(), total_allocation, token.clone())
            .unwrap();

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.mint(&env.current_contract_address(), &total_allocation);

        let now = env.ledger().timestamp();
        let vesting_start = now + 100;
        let vesting_end = now + 1000;
        let vesting_amount = 500000i128;

        schedule_vesting(
            &env,
            admin.clone(),
            user.clone(),
            epoch,
            vesting_amount,
            vesting_start,
            vesting_end,
        ).unwrap();

        // Try to claim before vesting start - should fail
        let result = claim_vested_emissions(&env, user.clone(), epoch);
        assert!(result.is_err());

        // Advance to vesting start
        env.ledger().with_mut(|li| {
            li.timestamp = vesting_start;
        });

        // Claim should work now
        let claimed = claim_vested_emissions(&env, user.clone(), epoch).unwrap();
        assert!(claimed > 0);
        assert!(claimed <= vesting_amount);
    }

    #[test]
    fn test_emissions_pause() {
        let (env, admin, user) = setup();
        initialize_emissions(&env, admin.clone(), 86400, 2592000).unwrap();

        let epoch = 1u64;
        let leaf = BytesN::from_array(&env, &[42u8; 32]);
        let root = leaf.clone();
        let token = Address::generate(&env);
        let total_allocation = 1000000i128;

        set_merkle_root(&env, admin.clone(), epoch, root.clone(), total_allocation, token.clone())
            .unwrap();

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.mint(&env.current_contract_address(), &total_allocation);

        // Pause emissions
        set_emissions_pause(&env, admin.clone(), true).unwrap();

        // Try to claim - should fail
        let result = claim_emissions(
            &env,
            user.clone(),
            ClaimInput {
                epoch,
                proof: create_test_proof(&env, leaf),
                amount: 100000,
            },
        );
        assert!(matches!(result, Err(EmissionsError::Paused)));

        // Unpause
        set_emissions_pause(&env, admin.clone(), false).unwrap();

        // Claim should work now
        let claimed = claim_emissions(
            &env,
            user.clone(),
            ClaimInput {
                epoch,
                proof: create_test_proof(&env, leaf),
                amount: 100000,
            },
        ).unwrap();
        assert_eq!(claimed, 100000);
    }

    #[test]
    fn test_invalid_proof() {
        let (env, admin, user) = setup();
        initialize_emissions(&env, admin.clone(), 86400, 2592000).unwrap();

        let epoch = 1u64;
        let root = BytesN::from_array(&env, &[1u8; 32]);
        let token = Address::generate(&env);

        set_merkle_root(&env, admin.clone(), epoch, root.clone(), 1000000, token.clone())
            .unwrap();

        // Wrong leaf
        let wrong_leaf = BytesN::from_array(&env, &[2u8; 32]);
        let proof = create_test_proof(&env, wrong_leaf);

        let result = claim_emissions(
            &env,
            user.clone(),
            ClaimInput {
                epoch,
                proof,
                amount: 100000,
            },
        );
        assert!(matches!(result, Err(EmissionsError::InvalidProof)));
    }
}