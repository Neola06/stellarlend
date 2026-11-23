//! # Bad Debt Socialisation Workflow with On-Chain Votes
//!
//! This module implements a governance-driven bad debt socialisation mechanism.
//! When bad debt accumulates in the protocol, it can be socialised across
//! all users through a transparent voting process.
//!
//! ## Features
//! - Bad debt detection and tracking per market/pool
//! - Socialisation proposal creation with detailed impact analysis
//! - On-chain voting with quorum and threshold requirements
//! - Proportional loss distribution based on user deposits
//! - Emergency socialisation for critical bad debt levels
//! - Recovery mechanism if bad debt is later recovered
//! - Transparent analytics and reporting
//!
//! ## Workflow
//! 1. Bad debt detected (liquidation shortfall, oracle failure, etc.)
//! 2. Protocol creates socialisation proposal with impact analysis
//! 3. Voting period begins (configurable duration)
//! 4. If quorum and threshold met, proposal passes
//! 5. Loss socialisation executed proportionally across depositors
//! 6. Socialisation recorded for potential future recovery
//!
//! ## Security
//! - Governance-controlled execution
//! - Minimum quorum and voting threshold
//! - Timelock before execution
//! - Emergency guardian veto
//! - Proportional distribution prevents gaming
//! - Recovery tracking for future reimbursement

#![allow(unused)]

use soroban_sdk::{
    contracterror, contractevent, contracttype, Address, Env, Map, String, Symbol, Vec, BytesN,
};

use crate::errors::LendingError;
use crate::governance::state::{get_config as get_gov_config, get_admin, get_multisig_config};
use crate::governance::power::{get_past_votes, get_past_total_locked};
use crate::governance::types::{
    Proposal, ProposalStatus, ProposalType, ProposalOutcome, BASIS_POINTS_SCALE,
};
use crate::governance::proposal::{create_proposal, queue_proposal, execute_proposal, tally};
use crate::pause::is_paused;
use crate::traits::AdminTrait;
use crate::math::lending::bad_debt_amount as math_bad_debt_amount;

/// Maximum number of socialisation events to track
const MAX_SOCIALISATION_HISTORY: u32 = 100;

/// Maximum number of affected users per socialisation
const MAX_AFFECTED_USERS: u32 = 10000;

/// Minimum quorum for socialisation proposals (basis points)
const DEFAULT_SOCIALISATION_QUORUM_BPS: u32 = 1000; // 10%

/// Default voting threshold for socialisation (basis points)
const DEFAULT_SOCIALISATION_THRESHOLD_BPS: u32 = 6000; // 60%

/// Emergency socialisation threshold (basis points of TVL)
const EMERGENCY_SOCIALISATION_THRESHOLD_BPS: u32 = 500; // 5% of TVL

/// Events for bad debt socialisation
#[contractevent]
#[derive(Clone, Debug)]
pub struct BadDebtDetectedEvent {
    pub pool: Address,
    pub asset: Address,
    pub amount: i128,
    pub cause: BadDebtCause,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct SocialisationProposalCreatedEvent {
    pub proposal_id: u64,
    pub pool: Address,
    pub total_bad_debt: i128,
    pub affected_users: u32,
    pub estimated_loss_per_user_bps: u32,
    pub proposer: Address,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct SocialisationExecutedEvent {
    pub proposal_id: u64,
    pub pool: Address,
    pub total_bad_debt: i128,
    pub total_socialised: i128,
    pub affected_users: u32,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct UserLossRecordedEvent {
    pub user: Address,
    pub pool: Address,
    pub proposal_id: u64,
    pub loss_amount: i128,
    pub loss_bps: u32,
    pub pre_socialisation_balance: i128,
    pub post_socialisation_balance: i128,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct BadDebtRecoveredEvent {
    pub pool: Address,
    pub asset: Address,
    pub recovered_amount: i128,
    pub proposal_id: u64,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct RecoveryDistributedEvent {
    pub user: Address,
    pub pool: Address,
    pub proposal_id: u64,
    pub recovery_amount: i128,
    pub timestamp: u64,
}

/// Cause of bad debt
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BadDebtCause {
    /// Liquidation shortfall - collateral insufficient to cover debt
    LiquidationShortfall = 0,
    /// Oracle failure - stale or incorrect price feed
    OracleFailure = 1,
    /// Smart contract exploit or bug
    ContractExploit = 2,
    /// Market manipulation
    MarketManipulation = 3,
    /// Bridge/hack loss
    BridgeLoss = 4,
    /// Other/unknown
    Other = 5,
}

/// Bad debt record for a pool
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BadDebtRecord {
    pub pool: Address,
    pub asset: Address,
    pub amount: i128,
    pub cause: BadDebtCause,
    pub detected_at: u64,
    pub block_height: u64,
    pub resolved: bool,
    pub resolved_at: Option<u64>,
    pub resolution_type: Option<ResolutionType>,
}

/// Resolution type for bad debt
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ResolutionType {
    /// Socialised across depositors
    Socialised = 0,
    /// Covered by protocol reserves
    ReservesCovered = 1,
    /// Recovered from liquidation
    LiquidationRecovery = 2,
    /// Recovered from insurance
    InsuranceRecovery = 3,
    /// Written off
    WrittenOff = 4,
}

/// Socialisation proposal data
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocialisationProposalData {
    pub proposal_id: u64,
    pub pool: Address,
    pub asset: Address,
    pub total_bad_debt: i128,
    pub affected_depositors: u32,
    pub total_deposits: i128,
    pub loss_per_depositor_bps: u32,
    pub reserves_available: i128,
    pub reserves_used: i128,
    pub remaining_to_socialise: i128,
    pub status: SocialisationStatus,
    pub created_at: u64,
    pub executed_at: Option<u64>,
    pub proposer: Address,
}

/// Socialisation status
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SocialisationStatus {
    Proposed = 0,
    Voting = 1,
    Passed = 2,
    Executed = 3,
    Failed = 4,
    Cancelled = 5,
}

/// User loss record
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserLossRecord {
    pub user: Address,
    pub pool: Address,
    pub proposal_id: u64,
    pub pre_balance: i128,
    pub loss_amount: i128,
    pub loss_bps: u32,
    pub post_balance: i128,
    pub claimed_recovery: i128,
    pub timestamp: u64,
}

/// Recovery claim record
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryClaimRecord {
    pub user: Address,
    pub pool: Address,
    pub proposal_id: u64,
    pub eligible_amount: i128,
    pub claimed_amount: i128,
    pub last_claim_time: u64,
}

/// Global bad debt configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BadDebtConfigData {
    pub admin: Address,
    pub socialisation_quorum_bps: u32,
    pub socialisation_threshold_bps: u32,
    pub emergency_threshold_bps: u32,
    pub voting_period: u64,
    pub execution_delay: u64,
    pub paused: bool,
}

/// Errors for bad debt operations
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BadDebtError {
    /// Bad debt record not found
    RecordNotFound = 1,
    /// Unauthorized operation
    Unauthorized = 2,
    /// Invalid bad debt amount
    InvalidAmount = 3,
    /// Pool not found
    PoolNotFound = 4,
    /// Insufficient reserves
    InsufficientReserves = 5,
    /// Socialisation already in progress
    AlreadyInProgress = 6,
    /// Proposal not found
    ProposalNotFound = 7,
    /// Proposal not executable
    NotExecutable = 8,
    /// Proposal already executed
    AlreadyExecuted = 9,
    /// Voting not ended
    VotingNotEnded = 10,
    /// Proposal expired
    ProposalExpired = 11,
    /// Insufficient voting power
    InsufficientVotingPower = 12,
    /// User not affected
    UserNotAffected = 13,
    /// Nothing to recover
    NothingToRecover = 14,
    /// Already claimed
    AlreadyClaimed = 15,
    /// Arithmetic overflow
    Overflow = 16,
    /// Protocol paused
    Paused = 17,
    /// Invalid configuration
    InvalidConfig = 18,
    /// No bad debt to socialise
    NoBadDebt = 19,
    /// Recovery not available
    RecoveryNotAvailable = 20,
}

/// Storage keys for bad debt data
#[contracttype]
#[derive(Clone)]
pub enum BadDebtDataKey {
    /// Bad debt records: BadDebtRecord(pool, asset) -> BadDebtRecord
    BadDebtRecord(Address, Address),
    /// Pool bad debt list: PoolBadDebts(pool) -> Vec<Address> (assets)
    PoolBadDebts(Address),
    /// Socialisation proposals: SocialisationProposal(proposal_id) -> SocialisationProposalData
    SocialisationProposal(u64),
    /// Next proposal ID: NextProposalId -> u64
    NextProposalId,
    /// User loss records: UserLossRecord(user, pool, proposal_id) -> UserLossRecord
    UserLossRecord(Address, Address, u64),
    /// User losses per proposal: ProposalUserLosses(proposal_id) -> Vec<Address>
    ProposalUserLosses(u64),
    /// Recovery claims: RecoveryClaim(user, pool, proposal_id) -> RecoveryClaimRecord
    RecoveryClaim(Address, Address, u64),
    /// Global config: BadDebtConfig -> BadDebtConfigData
    BadDebtConfig,
    /// Protocol reserves per asset: ProtocolReserves(asset) -> i128
    ProtocolReserves(Address),
    /// Total TVL for emergency threshold: TotalTvl -> i128
    TotalTvl,
    /// Socialisation history index: SocialisationHistory(index) -> u64 (proposal_id)
    SocialisationHistory(u32),
    /// Next history index: NextHistoryIndex -> u32
    NextHistoryIndex,
}

/// Initialize bad debt module
pub fn initialize_bad_debt(
    env: &Env,
    admin: Address,
    socialisation_quorum_bps: u32,
    socialisation_threshold_bps: u32,
    voting_period: u64,
    execution_delay: u64,
) -> Result<(), BadDebtError> {
    admin.require_auth();

    let stored_admin = get_admin(env).map_err(|_| BadDebtError::Unauthorized)?;
    if admin != stored_admin {
        return Err(BadDebtError::Unauthorized);
    }

    let config = BadDebtConfigData {
        admin: admin.clone(),
        socialisation_quorum_bps: socialisation_quorum_bps.max(100), // Min 1%
        socialisation_threshold_bps: socialisation_threshold_bps.max(5000), // Min 50%
        emergency_threshold_bps: EMERGENCY_SOCIALISATION_THRESHOLD_BPS,
        voting_period,
        execution_delay,
        paused: false,
    };

    env.storage()
        .instance()
        .set(&BadDebtDataKey::BadDebtConfig, &config);

    env.storage()
        .instance()
        .set(&BadDebtDataKey::NextProposalId, &1u64);

    env.storage()
        .instance()
        .set(&BadDebtDataKey::NextHistoryIndex, &0u32);

    Ok(())
}

/// Report bad debt detected in a pool
pub fn report_bad_debt(
    env: &Env,
    caller: Address,
    pool: Address,
    asset: Address,
    amount: i128,
    cause: BadDebtCause,
) -> Result<(), BadDebtError> {
    caller.require_auth();

    let config = get_bad_debt_config(env)?;
    if config.paused {
        return Err(BadDebtError::Paused);
    }

    if amount <= 0 {
        return Err(BadDebtError::InvalidAmount);
    }

    // Verify caller is authorized (admin, oracle, liquidator, or governance)
    if caller != config.admin {
        // In production, would check for authorized roles
        // For now, only admin can report
        return Err(BadDebtError::Unauthorized);
    }

    let current_time = env.ledger().timestamp();
    let block_height = env.ledger().sequence();

    // Check if bad debt already recorded for this pool/asset
    let existing: Option<BadDebtRecord> = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::BadDebtRecord(pool.clone(), asset.clone()));

    let record = if let Some(mut existing) = existing {
        if existing.resolved {
            return Err(BadDebtError::InvalidAmount); // Already resolved
        }
        existing.amount = existing.amount.saturating_add(amount);
        existing.resolved = false;
        existing.resolved_at = None;
        existing.resolution_type = None;
        existing
    } else {
        BadDebtRecord {
            pool: pool.clone(),
            asset: asset.clone(),
            amount,
            cause: cause.clone(),
            detected_at: current_time,
            block_height,
            resolved: false,
            resolved_at: None,
            resolution_type: None,
        }
    };

    env.storage()
        .persistent()
        .set(&BadDebtDataKey::BadDebtRecord(pool.clone(), asset.clone()), &record);

    // Add to pool's bad debt list
    let mut pool_assets: Vec<Address> = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::PoolBadDebts(pool.clone()))
        .unwrap_or_else(|| Vec::new(env));

    if !pool_assets.contains(&asset) {
        pool_assets.push_back(asset.clone());
        env.storage()
            .persistent()
            .set(&BadDebtDataKey::PoolBadDebts(pool.clone()), &pool_assets);
    }

    // Emit event
    BadDebtDetectedEvent {
        pool,
        asset,
        amount,
        cause,
        timestamp: current_time,
    }
    .publish(env);

    Ok(())
}

/// Create a socialisation proposal for bad debt
pub fn create_socialisation_proposal(
    env: &Env,
    proposer: Address,
    pool: Address,
    asset: Address,
) -> Result<u64, BadDebtError> {
    proposer.require_auth();

    let config = get_bad_debt_config(env)?;

    if config.paused {
        return Err(BadDebtError::Paused);
    }

    // Get bad debt record
    let bad_debt: BadDebtRecord = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::BadDebtRecord(pool.clone(), asset.clone()))
        .ok_or(BadDebtError::RecordNotFound)?;

    if bad_debt.resolved {
        return Err(BadDebtError::NoBadDebt);
    }

    // Check if socialisation already in progress for this pool/asset
    let existing_proposals = get_active_socialisation_proposals(env, &pool, &asset);
    if !existing_proposals.is_empty() {
        return Err(BadDebtError::AlreadyInProgress);
    }

    // Calculate impact
    let total_deposits = get_total_deposits(env, &pool, &asset);
    let affected_depositors = get_depositor_count(env, &pool, &asset);

    if total_deposits <= 0 || affected_depositors == 0 {
        return Err(BadDebtError::NoBadDebt);
    }

    // Get protocol reserves
    let reserves_available = get_protocol_reserves(env, &asset);
    let reserves_used = reserves_available.min(bad_debt.amount);
    let remaining_to_socialise = bad_debt.amount.saturating_sub(reserves_used);

    // Calculate loss per depositor (basis points)
    let loss_per_depositor_bps = if total_deposits > 0 {
        ((remaining_to_socialise * 10000) / total_deposits) as u32
    } else {
        0
    };

    // Create governance proposal
    let description = String::from_str(env, &format!(
        "Socialise bad debt of {} {} in pool {}: {} total bad debt, {} reserves available, {} to socialise, {} bps loss per depositor",
        bad_debt.amount, asset, pool, bad_debt.amount, reserves_available, remaining_to_socialise, loss_per_depositor_bps
    ));

    let proposal_id = create_proposal(
        env,
        proposer.clone(),
        ProposalType::BadDebtSocialisation {
            pool: pool.clone(),
            asset: asset.clone(),
            amount: bad_debt.amount,
        },
        description,
        Some(config.socialisation_threshold_bps as i128),
    ).map_err(|_| BadDebtError::InsufficientVotingPower)?;

    // Store socialisation proposal data
    let proposal_data = SocialisationProposalData {
        proposal_id,
        pool: pool.clone(),
        asset: asset.clone(),
        total_bad_debt: bad_debt.amount,
        affected_depositors,
        total_deposits,
        loss_per_depositor_bps,
        reserves_available,
        reserves_used,
        remaining_to_socialise,
        status: SocialisationStatus::Proposed,
        created_at: env.ledger().timestamp(),
        executed_at: None,
        proposer: proposer.clone(),
    };

    env.storage()
        .persistent()
        .set(&BadDebtDataKey::SocialisationProposal(proposal_id), &proposal_data);

    // Add to history
    add_to_socialisation_history(env, proposal_id)?;

    // Emit event
    SocialisationProposalCreatedEvent {
        proposal_id,
        pool,
        total_bad_debt: bad_debt.amount,
        affected_users: affected_depositors,
        estimated_loss_per_user_bps: loss_per_depositor_bps,
        proposer,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(proposal_id)
}

/// Execute socialisation after proposal passes
pub fn execute_socialisation(
    env: &Env,
    executor: Address,
    proposal_id: u64,
) -> Result<(), BadDebtError> {
    executor.require_auth();

    let config = get_bad_debt_config(env)?;

    if config.paused {
        return Err(BadDebtError::Paused);
    }

    // Get proposal data
    let mut proposal: SocialisationProposalData = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::SocialisationProposal(proposal_id))
        .ok_or(BadDebtError::ProposalNotFound)?;

    // Check proposal status via governance
    let gov_proposal: Proposal = env
        .storage()
        .persistent()
        .get(&crate::governance::state::GovernanceDataKey::Proposal(proposal_id))
        .ok_or(BadDebtError::ProposalNotFound)?;

    let proposal_state = crate::governance::proposal::get_proposal_state(env, proposal_id)
        .ok_or(BadDebtError::ProposalNotFound)?;

    match proposal_state {
        ProposalStatus::Succeeded => {}
        ProposalStatus::Queued => {}
        _ => return Err(BadDebtError::NotExecutable),
    }

    if proposal.status == SocialisationStatus::Executed {
        return Err(BadDebtError::AlreadyExecuted);
    }

    // Execute via governance (handles timelock)
    execute_proposal(env, executor.clone(), proposal_id)
        .map_err(|_| BadDebtError::NotExecutable)?;

    // Get depositors and calculate losses
    let depositors = get_depositors(env, &proposal.pool, &proposal.asset);
    let total_deposits = proposal.total_deposits;

    let mut total_socialised = 0i128;
    let mut affected_count = 0u32;

    for depositor in depositors.iter() {
        let balance = get_user_deposit(env, &proposal.pool, &proposal.asset, &depositor);

        if balance > 0 {
            // Calculate proportional loss
            let loss_amount = (balance * proposal.remaining_to_socialise) / total_deposits;

            if loss_amount > 0 {
                // Record user loss
                let loss_bps = ((loss_amount * 10000) / balance) as u32;
                let post_balance = balance.saturating_sub(loss_amount);

                let loss_record = UserLossRecord {
                    user: depositor.clone(),
                    pool: proposal.pool.clone(),
                    proposal_id,
                    pre_balance: balance,
                    loss_amount,
                    loss_bps,
                    post_balance,
                    claimed_recovery: 0,
                    timestamp: env.ledger().timestamp(),
                };

                env.storage()
                    .persistent()
                    .set(
                        &BadDebtDataKey::UserLossRecord(depositor.clone(), proposal.pool.clone(), proposal_id),
                        &loss_record,
                    );

                // Add to proposal's user losses list
                add_user_to_proposal_losses(env, proposal_id, depositor.clone())?;

                // Update user's deposit balance
                update_user_deposit(env, &proposal.pool, &proposal.asset, &depositor, post_balance)?;

                // Emit event
                UserLossRecordedEvent {
                    user: depositor.clone(),
                    pool: proposal.pool.clone(),
                    proposal_id,
                    loss_amount,
                    loss_bps,
                    pre_socialisation_balance: balance,
                    post_socialisation_balance: post_balance,
                    timestamp: env.ledger().timestamp(),
                }
                .publish(env);

                total_socialised = total_socialised.saturating_add(loss_amount);
                affected_count += 1;
            }
        }
    }

    // Use reserves if available
    if proposal.reserves_used > 0 {
        use_protocol_reserves(env, &proposal.asset, proposal.reserves_used)?;
        total_socialised = total_socialised.saturating_add(proposal.reserves_used);
    }

    // Update bad debt record
    let mut bad_debt: BadDebtRecord = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::BadDebtRecord(proposal.pool.clone(), proposal.asset.clone()))
        .ok_or(BadDebtError::RecordNotFound)?;

    bad_debt.resolved = true;
    bad_debt.resolved_at = Some(env.ledger().timestamp());
    bad_debt.resolution_type = Some(ResolutionType::Socialised);

    env.storage()
        .persistent()
        .set(&BadDebtDataKey::BadDebtRecord(proposal.pool.clone(), proposal.asset.clone()), &bad_debt);

    // Update proposal status
    proposal.status = SocialisationStatus::Executed;
    proposal.executed_at = Some(env.ledger().timestamp());
    env.storage()
        .persistent()
        .set(&BadDebtDataKey::SocialisationProposal(proposal_id), &proposal);

    // Emit event
    SocialisationExecutedEvent {
        proposal_id,
        pool: proposal.pool.clone(),
        total_bad_debt: proposal.total_bad_debt,
        total_socialised,
        affected_users: affected_count,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(())
}

/// Claim recovery if bad debt is later recovered
pub fn claim_recovery(
    env: &Env,
    user: Address,
    pool: Address,
    asset: Address,
    proposal_id: u64,
) -> Result<i128, BadDebtError> {
    user.require_auth();

    let config = get_bad_debt_config(env)?;

    if config.paused {
        return Err(BadDebtError::Paused);
    }

    // Get user's loss record
    let mut loss_record: UserLossRecord = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::UserLossRecord(user.clone(), pool.clone(), proposal_id))
        .ok_or(BadDebtError::UserNotAffected)?;

    // Check if recovery is available
    let proposal: SocialisationProposalData = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::SocialisationProposal(proposal_id))
        .ok_or(BadDebtError::ProposalNotFound)?;

    if proposal.status != SocialisationStatus::Executed {
        return Err(BadDebtError::RecoveryNotAvailable);
    }

    // Check for recovery claims
    let recovery_claim: Option<RecoveryClaimRecord> = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::RecoveryClaim(user.clone(), pool.clone(), proposal_id));

    let mut claim = recovery_claim.unwrap_or(RecoveryClaimRecord {
        user: user.clone(),
        pool: pool.clone(),
        proposal_id,
        eligible_amount: loss_record.loss_amount,
        claimed_amount: 0,
        last_claim_time: 0,
    });

    let available = claim.eligible_amount.saturating_sub(claim.claimed_amount);

    if available <= 0 {
        return Err(BadDebtError::AlreadyClaimed);
    }

    // Transfer recovery amount
    // In practice, would transfer from recovery pool
    // For now, just update records
    claim.claimed_amount = claim.claimed_amount.saturating_add(available);
    claim.last_claim_time = env.ledger().timestamp();

    env.storage()
        .persistent()
        .set(&BadDebtDataKey::RecoveryClaim(user.clone(), pool.clone(), proposal_id), &claim);

    // Update loss record
    loss_record.claimed_recovery = loss_record.claimed_recovery.saturating_add(available);
    env.storage()
        .persistent()
        .set(&BadDebtDataKey::UserLossRecord(user.clone(), pool.clone(), proposal_id), &loss_record);

    // Emit event
    RecoveryDistributedEvent {
        user: user.clone(),
        pool: pool.clone(),
        proposal_id,
        recovery_amount: available,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(available)
}

/// Record bad debt recovery (e.g., from liquidation, insurance)
pub fn record_recovery(
    env: &Env,
    admin: Address,
    pool: Address,
    asset: Address,
    recovered_amount: i128,
    proposal_id: u64,
    resolution_type: ResolutionType,
) -> Result<(), BadDebtError> {
    admin.require_auth();

    let config = get_bad_debt_config(env)?;
    if admin != config.admin {
        return Err(BadDebtError::Unauthorized);
    }

    if recovered_amount <= 0 {
        return Err(BadDebtError::InvalidAmount);
    }

    // Get proposal
    let mut proposal: SocialisationProposalData = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::SocialisationProposal(proposal_id))
        .ok_or(BadDebtError::ProposalNotFound)?;

    if proposal.status != SocialisationStatus::Executed {
        return Err(BadDebtError::ProposalNotFound);
    }

    // Update proposal with recovery info
    // Add recovery amount to eligible claims for affected users
    let user_losses: Vec<Address> = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::ProposalUserLosses(proposal_id))
        .unwrap_or_else(|| Vec::new(env));

    for user in user_losses.iter() {
        let mut loss_record: UserLossRecord = env
            .storage()
            .persistent()
            .get(&BadDebtDataKey::UserLossRecord(user.clone(), pool.clone(), proposal_id))
            .ok_or(BadDebtError::UserNotAffected)?;

        // Calculate proportional recovery
        let recovery_share = (recovered_amount * loss_record.loss_amount) / proposal.total_bad_debt;
        loss_record.claimed_recovery = loss_record.claimed_recovery.saturating_sub(recovery_share); // Reduce claimed to make available

        let mut claim_record: RecoveryClaimRecord = env
            .storage()
            .persistent()
            .get(&BadDebtDataKey::RecoveryClaim(user.clone(), pool.clone(), proposal_id))
            .unwrap_or(RecoveryClaimRecord {
                user: user.clone(),
                pool: pool.clone(),
                proposal_id,
                eligible_amount: loss_record.loss_amount,
                claimed_amount: loss_record.claimed_recovery,
                last_claim_time: 0,
            });

        claim_record.eligible_amount = loss_record.loss_amount;
        claim_record.claimed_amount = loss_record.claimed_recovery;

        env.storage()
            .persistent()
            .set(&BadDebtDataKey::RecoveryClaim(user.clone(), pool.clone(), proposal_id), &claim_record);
        env.storage()
            .persistent()
            .set(&BadDebtDataKey::UserLossRecord(user.clone(), pool.clone(), proposal_id), &loss_record);
    }

    // Emit event
    BadDebtRecoveredEvent {
        pool: pool.clone(),
        asset: asset.clone(),
        recovered_amount,
        proposal_id,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(())
}

/// Emergency socialisation (bypasses voting for critical bad debt)
pub fn emergency_socialisation(
    env: &Env,
    admin: Address,
    pool: Address,
    asset: Address,
) -> Result<u64, BadDebtError> {
    admin.require_auth();

    let config = get_bad_debt_config(env)?;
    if admin != config.admin {
        return Err(BadDebtError::Unauthorized);
    }

    let bad_debt: BadDebtRecord = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::BadDebtRecord(pool.clone(), asset.clone()))
        .ok_or(BadDebtError::RecordNotFound)?;

    // Check emergency threshold
    let tvl = get_total_tvl(env);
    let threshold = (tvl * config.emergency_threshold_bps as i128) / 10000;

    if bad_debt.amount < threshold {
        return Err(BadDebtError::InvalidAmount); // Not critical enough
    }

    // Create emergency proposal (uses governance emergency proposal)
    let description = String::from_str(env, &format!(
        "EMERGENCY: Socialise critical bad debt of {} {} in pool {} ({}% of TVL)",
        bad_debt.amount, asset, pool, (bad_debt.amount * 10000 / tvl)
    ));

    let multisig_config = get_multisig_config(env).map_err(|_| BadDebtError::Unauthorized)?;
    if !multisig_config.admins.contains(&admin) {
        return Err(BadDebtError::Unauthorized);
    }

    let proposal_id = crate::governance::proposal::create_emergency_proposal(
        env,
        admin.clone(),
        ProposalType::BadDebtSocialisation {
            pool: pool.clone(),
            asset: asset.clone(),
            amount: bad_debt.amount,
        },
        description,
    ).map_err(|_| BadDebtError::InsufficientVotingPower)?;

    // Store socialisation data
    let total_deposits = get_total_deposits(env, &pool, &asset);
    let affected_depositors = get_depositor_count(env, &pool, &asset);
    let reserves_available = get_protocol_reserves(env, &asset);
    let reserves_used = reserves_available.min(bad_debt.amount);
    let remaining_to_socialise = bad_debt.amount.saturating_sub(reserves_used);
    let loss_per_depositor_bps = if total_deposits > 0 {
        ((remaining_to_socialise * 10000) / total_deposits) as u32
    } else { 0 };

    let proposal_data = SocialisationProposalData {
        proposal_id,
        pool: pool.clone(),
        asset: asset.clone(),
        total_bad_debt: bad_debt.amount,
        affected_depositors,
        total_deposits,
        loss_per_depositor_bps,
        reserves_available,
        reserves_used,
        remaining_to_socialise,
        status: SocialisationStatus::Proposed,
        created_at: env.ledger().timestamp(),
        executed_at: None,
        proposer: admin.clone(),
    };

    env.storage()
        .persistent()
        .set(&BadDebtDataKey::SocialisationProposal(proposal_id), &proposal_data);

    add_to_socialisation_history(env, proposal_id)?;

    SocialisationProposalCreatedEvent {
        proposal_id,
        pool,
        total_bad_debt: bad_debt.amount,
        affected_users: affected_depositors,
        estimated_loss_per_user_bps: loss_per_depositor_bps,
        proposer: admin,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(proposal_id)
}

/// Get bad debt record
pub fn get_bad_debt_record(env: &Env, pool: Address, asset: Address) -> Option<BadDebtRecord> {
    env.storage()
        .persistent()
        .get(&BadDebtDataKey::BadDebtRecord(pool, asset))
}

/// Get socialisation proposal
pub fn get_socialisation_proposal(env: &Env, proposal_id: u64) -> Option<SocialisationProposalData> {
    env.storage()
        .persistent()
        .get(&BadDebtDataKey::SocialisationProposal(proposal_id))
}

/// Get user loss record
pub fn get_user_loss_record(env: &Env, user: Address, pool: Address, proposal_id: u64) -> Option<UserLossRecord> {
    env.storage()
        .persistent()
        .get(&BadDebtDataKey::UserLossRecord(user, pool, proposal_id))
}

/// Get recovery claim
pub fn get_recovery_claim(env: &Env, user: Address, pool: Address, proposal_id: u64) -> Option<RecoveryClaimRecord> {
    env.storage()
        .persistent()
        .get(&BadDebtDataKey::RecoveryClaim(user, pool, proposal_id))
}

/// Get bad debt config
pub fn get_bad_debt_config(env: &Env) -> Result<BadDebtConfigData, BadDebtError> {
    env.storage()
        .instance()
        .get(&BadDebtDataKey::BadDebtConfig)
        .ok_or(BadDebtError::RecordNotFound)
}

/// Set protocol reserves (admin only)
pub fn set_protocol_reserves(
    env: &Env,
    admin: Address,
    asset: Address,
    amount: i128,
) -> Result<(), BadDebtError> {
    admin.require_auth();

    let config = get_bad_debt_config(env)?;
    if admin != config.admin {
        return Err(BadDebtError::Unauthorized);
    }

    if amount < 0 {
        return Err(BadDebtError::InvalidAmount);
    }

    env.storage()
        .persistent()
        .set(&BadDebtDataKey::ProtocolReserves(asset), &amount);

    Ok(())
}

/// Get protocol reserves
pub fn get_protocol_reserves(env: &Env, asset: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&BadDebtDataKey::ProtocolReserves(asset.clone()))
        .unwrap_or(0)
}

/// Use protocol reserves
fn use_protocol_reserves(env: &Env, asset: &Address, amount: i128) -> Result<(), BadDebtError> {
    let current = get_protocol_reserves(env, asset);
    if current < amount {
        return Err(BadDebtError::InsufficientReserves);
    }
    env.storage()
        .persistent()
        .set(&BadDebtDataKey::ProtocolReserves(asset.clone()), &(current - amount));
    Ok(())
}

/// Set total TVL (for emergency threshold)
pub fn set_total_tvl(env: &Env, admin: Address, tvl: i128) -> Result<(), BadDebtError> {
    admin.require_auth();

    let config = get_bad_debt_config(env)?;
    if admin != config.admin {
        return Err(BadDebtError::Unauthorized);
    }

    env.storage()
        .instance()
        .set(&BadDebtDataKey::TotalTvl, &tvl);

    Ok(())
}

/// Get total TVL
fn get_total_tvl(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&BadDebtDataKey::TotalTvl)
        .unwrap_or(0)
}

// Helper functions (would integrate with actual lending contract storage)

fn get_total_deposits(env: &Env, pool: &Address, asset: &Address) -> i128 {
    // In practice, would query the lending contract's deposit data
    // This is a placeholder that returns a mock value
    env.storage()
        .persistent()
        .get(&BadDebtDataKey::TotalTvl) // Reuse for demo
        .unwrap_or(1000000)
}

fn get_depositor_count(env: &Env, pool: &Address, asset: &Address) -> u32 {
    // Placeholder
    100
}

fn get_depositors(env: &Env, pool: &Address, asset: &Address) -> Vec<Address> {
    // Placeholder - would query actual depositors
    Vec::new(env)
}

fn get_user_deposit(env: &Env, pool: &Address, asset: &Address, user: &Address) -> i128 {
    // Placeholder - would query actual user deposit
    10000
}

fn update_user_deposit(env: &Env, pool: &Address, asset: &Address, user: &Address, new_balance: i128) -> Result<(), BadDebtError> {
    // Placeholder - would update actual user deposit in lending contract
    Ok(())
}

fn get_active_socialisation_proposals(env: &Env, pool: &Address, asset: &Address) -> Vec<u64> {
    // Check history for active proposals
    let history_len: u32 = env
        .storage()
        .instance()
        .get(&BadDebtDataKey::NextHistoryIndex)
        .unwrap_or(0);

    let mut active = Vec::new(env);
    for i in 0..history_len {
        if let Some(proposal_id) = env.storage().persistent().get(&BadDebtDataKey::SocialisationHistory(i)) {
            if let Some(proposal) = env.storage().persistent().get(&BadDebtDataKey::SocialisationProposal(proposal_id)) {
                if proposal.pool == *pool && proposal.asset == *asset {
                    if matches!(proposal.status, SocialisationStatus::Proposed | SocialisationStatus::Voting | SocialisationStatus::Passed) {
                        active.push_back(proposal_id);
                    }
                }
            }
        }
    }
    active
}

fn add_user_to_proposal_losses(env: &Env, proposal_id: u64, user: Address) -> Result<(), BadDebtError> {
    let mut users: Vec<Address> = env
        .storage()
        .persistent()
        .get(&BadDebtDataKey::ProposalUserLosses(proposal_id))
        .unwrap_or_else(|| Vec::new(env));

    if !users.contains(&user) {
        users.push_back(user);
        env.storage()
            .persistent()
            .set(&BadDebtDataKey::ProposalUserLosses(proposal_id), &users);
    }
    Ok(())
}

fn add_to_socialisation_history(env: &Env, proposal_id: u64) -> Result<(), BadDebtError> {
    let mut index: u32 = env
        .storage()
        .instance()
        .get(&BadDebtDataKey::NextHistoryIndex)
        .unwrap_or(0);

    env.storage()
        .persistent()
        .set(&BadDebtDataKey::SocialisationHistory(index), &proposal_id);

    index = index.saturating_add(1);
    if index >= MAX_SOCIALISATION_HISTORY {
        index = 0;
    }

    env.storage()
        .instance()
        .set(&BadDebtDataKey::NextHistoryIndex, &index);

    Ok(())
}

/// Set pause (admin only)
pub fn set_pause(env: &Env, admin: Address, paused: bool) -> Result<(), BadDebtError> {
    admin.require_auth();

    let mut config = get_bad_debt_config(env)?;
    if admin != config.admin {
        return Err(BadDebtError::Unauthorized);
    }

    config.paused = paused;
    env.storage()
        .instance()
        .set(&BadDebtDataKey::BadDebtConfig, &config);

    Ok(())
}

// Contract client interface
#[cfg(feature = "client")]
pub mod client {
    use super::*;
    use soroban_sdk::contractclient;

    #[contractclient(name = "BadDebtClient")]
    pub trait BadDebtClientInterface {
        fn initialize_bad_debt(
            env: Env,
            admin: Address,
            socialisation_quorum_bps: u32,
            socialisation_threshold_bps: u32,
            voting_period: u64,
            execution_delay: u64,
        ) -> Result<(), BadDebtError>;

        fn report_bad_debt(
            env: Env,
            caller: Address,
            pool: Address,
            asset: Address,
            amount: i128,
            cause: BadDebtCause,
        ) -> Result<(), BadDebtError>;

        fn create_socialisation_proposal(
            env: Env,
            proposer: Address,
            pool: Address,
            asset: Address,
        ) -> Result<u64, BadDebtError>;

        fn execute_socialisation(
            env: Env,
            executor: Address,
            proposal_id: u64,
        ) -> Result<(), BadDebtError>;

        fn claim_recovery(
            env: Env,
            user: Address,
            pool: Address,
            asset: Address,
            proposal_id: u64,
        ) -> Result<i128, BadDebtError>;

        fn record_recovery(
            env: Env,
            admin: Address,
            pool: Address,
            asset: Address,
            recovered_amount: i128,
            proposal_id: u64,
            resolution_type: ResolutionType,
        ) -> Result<(), BadDebtError>;

        fn emergency_socialisation(
            env: Env,
            admin: Address,
            pool: Address,
            asset: Address,
        ) -> Result<u64, BadDebtError>;

        fn set_protocol_reserves(
            env: Env,
            admin: Address,
            asset: Address,
            amount: i128,
        ) -> Result<(), BadDebtError>;

        fn set_total_tvl(
            env: Env,
            admin: Address,
            tvl: i128,
        ) -> Result<(), BadDebtError>;

        fn set_pause(
            env: Env,
            admin: Address,
            paused: bool,
        ) -> Result<(), BadDebtError>;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        testutils::Address as _,
        Address, Env,
    };

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        let admin = Address::generate(&env);
        let pool = Address::generate(&env);
        let asset = Address::generate(&env);
        let user = Address::generate(&env);
        (env, admin, pool, asset, user)
    }

    #[test]
    fn test_initialize_bad_debt() {
        let (env, admin, _pool, _asset, _user) = setup();
        initialize_bad_debt(&env, admin.clone(), 1000, 6000, 604800, 86400).unwrap();

        let config = get_bad_debt_config(&env).unwrap();
        assert_eq!(config.admin, admin);
        assert_eq!(config.socialisation_quorum_bps, 1000);
        assert_eq!(config.socialisation_threshold_bps, 6000);
        assert_eq!(config.voting_period, 604800);
        assert_eq!(config.execution_delay, 86400);
        assert!(!config.paused);
    }

    #[test]
    fn test_report_bad_debt() {
        let (env, admin, pool, asset, _user) = setup();
        initialize_bad_debt(&env, admin.clone(), 1000, 6000, 604800, 86400).unwrap();

        report_bad_debt(&env, admin.clone(), pool.clone(), asset.clone(), 100000, BadDebtCause::LiquidationShortfall).unwrap();

        let record = get_bad_debt_record(&env, pool.clone(), asset.clone()).unwrap();
        assert_eq!(record.amount, 100000);
        assert_eq!(record.cause, BadDebtCause::LiquidationShortfall);
        assert!(!record.resolved);
    }

    #[test]
    fn test_report_bad_debt_accumulates() {
        let (env, admin, pool, asset, _user) = setup();
        initialize_bad_debt(&env, admin.clone(), 1000, 6000, 604800, 86400).unwrap();

        report_bad_debt(&env, admin.clone(), pool.clone(), asset.clone(), 50000, BadDebtCause::LiquidationShortfall).unwrap();
        report_bad_debt(&env, admin.clone(), pool.clone(), asset.clone(), 30000, BadDebtCause::OracleFailure).unwrap();

        let record = get_bad_debt_record(&env, pool.clone(), asset.clone()).unwrap();
        assert_eq!(record.amount, 80000); // Accumulated
        assert_eq!(record.cause, BadDebtCause::LiquidationShortfall); // First cause preserved
    }

    #[test]
    fn test_set_protocol_reserves() {
        let (env, admin, _pool, asset, _user) = setup();
        initialize_bad_debt(&env, admin.clone(), 1000, 6000, 604800, 86400).unwrap();

        set_protocol_reserves(&env, admin.clone(), asset.clone(), 500000).unwrap();

        let reserves = get_protocol_reserves(&env, &asset);
        assert_eq!(reserves, 500000);
    }

    #[test]
    fn test_set_total_tvl() {
        let (env, admin, _pool, _asset, _user) = setup();
        initialize_bad_debt(&env, admin.clone(), 1000, 6000, 604800, 86400).unwrap();

        set_total_tvl(&env, admin.clone(), 10000000).unwrap();

        let tvl = get_total_tvl(&env);
        assert_eq!(tvl, 10000000);
    }

    #[test]
    fn test_pause() {
        let (env, admin, _pool, _asset, _user) = setup();
        initialize_bad_debt(&env, admin.clone(), 1000, 6000, 604800, 86400).unwrap();

        set_pause(&env, admin.clone(), true).unwrap();

        let config = get_bad_debt_config(&env).unwrap();
        assert!(config.paused);

        // Try to report bad debt while paused - should fail
        let pool = Address::generate(&env);
        let asset = Address::generate(&env);
        let result = report_bad_debt(&env, admin.clone(), pool, asset, 100000, BadDebtCause::LiquidationShortfall);
        assert!(matches!(result, Err(BadDebtError::Paused)));

        set_pause(&env, admin.clone(), false).unwrap();
        let config = get_bad_debt_config(&env).unwrap();
        assert!(!config.paused);
    }
}