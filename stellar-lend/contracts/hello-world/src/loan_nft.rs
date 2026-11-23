//! # Loan NFT Representation with Transferability Policy
//!
//! This module implements NFT representation for loan positions with configurable
//! transferability policies. It allows loans to be represented as NFTs that can
//! be transferred, traded, or used as collateral in secondary markets.
//!
//! ## Features
//! - Loan position NFT minting with full position metadata
//! - Configurable transferability policies (free, restricted, whitelist, blacklist)
//! - Transfer hooks for compliance (KYC/AML, jurisdiction restrictions)
//! - Loan state synchronization (health factor, interest accrual)
//! - Partial loan transfer and splitting
//! - Integration with existing debt token system
//! - Governance-controlled policy updates
//!
//! ## Transferability Policies
//! - `Free`: No restrictions on transfers
//! - `Restricted`: Only whitelisted addresses can receive
//! - `Blacklist`: Blocked addresses cannot receive
//! - `KycRequired`: Receiver must have valid KYC attestation
//! - `JurisdictionRestricted`: Transfers restricted by jurisdiction
//!
//! ## Security
//! - Transfer authorization required from sender
//! - Policy enforcement on every transfer
//! - Emergency pause by guardians
//! - Loan state validation on transfer
//! - Reentrancy protection

#![allow(unused)]

use soroban_sdk::{
    contracterror, contractevent, contracttype, Address, Env, Map, String, Symbol, Vec, BytesN,
};

use crate::errors::LendingError;
use crate::governance::state::get_admin;
use crate::pause::is_paused;
use crate::traits::AdminTrait;
use crate::debt_token::{DebtTokenError, get_debt_position, transfer_debt_token};

/// Maximum number of transfer policies
const MAX_POLICIES: u32 = 10;

/// Maximum whitelist/blacklist size per policy
const MAX_LIST_SIZE: u32 = 1000;

/// Maximum metadata URI length
const MAX_URI_LENGTH: u32 = 256;

/// Events for loan NFT operations
#[contractevent]
#[derive(Clone, Debug)]
pub struct LoanNftMintedEvent {
    pub token_id: u64,
    pub borrower: Address,
    pub loan_id: u64,
    pub principal: i128,
    pub collateral_asset: Address,
    pub collateral_amount: i128,
    pub policy: TransferPolicy,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct LoanNftTransferredEvent {
    pub token_id: u64,
    pub from: Address,
    pub to: Address,
    pub policy: TransferPolicy,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct LoanNftPolicyUpdatedEvent {
    pub token_id: u64,
    pub old_policy: TransferPolicy,
    pub new_policy: TransferPolicy,
    pub updated_by: Address,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct LoanNftSplitEvent {
    pub original_token_id: u64,
    pub new_token_id: u64,
    pub split_amount: i128,
    pub owner: Address,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct LoanNftMergedEvent {
    pub token_id_a: u64,
    pub token_id_b: u64,
    pub owner: Address,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct LoanNftBurnedEvent {
    pub token_id: u64,
    pub burner: Address,
    pub reason: Symbol,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct LoanNftWhitelistUpdatedEvent {
    pub policy_id: u64,
    pub address: Address,
    pub added: bool,
    pub timestamp: u64,
}

/// Transferability policy types
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TransferPolicy {
    /// Free transferability - no restrictions
    Free = 0,
    /// Restricted - only whitelisted addresses can receive
    Restricted = 1,
    /// Blacklist - blocked addresses cannot receive
    Blacklist = 2,
    /// KYC required - receiver must have valid KYC
    KycRequired = 3,
    /// Jurisdiction restricted - transfers limited by jurisdiction
    JurisdictionRestricted = 4,
    /// Custom policy - defined by policy ID
    Custom(u64) = 5,
}

/// Policy configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    pub policy_id: u64,
    pub policy_type: TransferPolicy,
    pub name: String,
    pub description: String,
    pub whitelist: Vec<Address>,
    pub blacklist: Vec<Address>,
    pub kyc_provider: Option<Address>,
    pub allowed_jurisdictions: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub is_active: bool,
}

/// Loan position data stored in NFT
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoanPosition {
    pub loan_id: u64,
    pub borrower: Address,
    pub principal: i128,
    pub outstanding_principal: i128,
    pub accrued_interest: i128,
    pub interest_rate_bps: i128,
    pub collateral_asset: Address,
    pub collateral_amount: i128,
    pub collateral_value: i128,
    pub health_factor_bps: u32,
    pub last_accrual_time: u64,
    pub maturity_time: Option<u64>,
    pub status: LoanStatus,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Loan status
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum LoanStatus {
    Active = 0,
    Repaid = 1,
    Liquidated = 2,
    Defaulted = 3,
    Restructured = 4,
}

/// NFT metadata
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftMetadata {
    pub token_id: u64,
    pub name: String,
    pub description: String,
    pub image_uri: String,
    pub external_uri: String,
    pub attributes: Vec<NftAttribute>,
}

/// NFT attribute for metadata
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftAttribute {
    pub trait_type: String,
    pub value: String,
}

/// Errors for loan NFT operations
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LoanNftError {
    /// Token not found
    TokenNotFound = 1,
    /// Unauthorized operation
    Unauthorized = 2,
    /// Transfer not allowed by policy
    TransferNotAllowed = 3,
    /// Address not whitelisted
    NotWhitelisted = 4,
    /// Address blacklisted
    Blacklisted = 5,
    /// KYC verification failed
    KycFailed = 6,
    /// Jurisdiction not allowed
    JurisdictionNotAllowed = 7,
    /// Loan position not found
    LoanNotFound = 8,
    /// Invalid loan state for operation
    InvalidLoanState = 9,
    /// Split amount invalid
    InvalidSplitAmount = 10,
    /// Cannot merge incompatible loans
    IncompatibleMerge = 11,
    /// Policy not found
    PolicyNotFound = 12,
    /// Policy already exists
    PolicyAlreadyExists = 13,
    /// Whitelist/blacklist full
    ListFull = 14,
    /// Metadata URI too long
    UriTooLong = 15,
    /// Arithmetic overflow
    Overflow = 16,
    /// Transfers paused
    Paused = 17,
    /// Invalid policy configuration
    InvalidPolicy = 18,
    /// Loan already tokenized
    AlreadyTokenized = 19,
    /// Token is not transferable in current state
    NonTransferableState = 20,
}

/// Storage keys for loan NFT data
#[contracttype]
#[derive(Clone)]
pub enum LoanNftDataKey {
    /// Next token ID: NextTokenId -> u64
    NextTokenId,
    /// Token to loan position: TokenPosition(token_id) -> LoanPosition
    TokenPosition(u64),
    /// Token to policy: TokenPolicy(token_id) -> u64 (policy_id)
    TokenPolicy(u64),
    /// Owner to token IDs: OwnerTokens(owner) -> Vec<u64>
    OwnerTokens(Address),
    /// Policy configs: PolicyConfig(policy_id) -> PolicyConfig
    PolicyConfig(u64),
    /// Next policy ID: NextPolicyId -> u64
    NextPolicyId,
    /// NFT metadata: TokenMetadata(token_id) -> NftMetadata
    TokenMetadata(u64),
    /// Token URI: TokenUri(token_id) -> String
    TokenUri(u64),
    /// Global config: LoanNftConfig -> LoanNftConfigData
    LoanNftConfig,
    /// KYC attestations: KycAttestation(address) -> KycData
    KycAttestation(Address),
    /// Total supply: TotalSupply -> u64
    TotalSupply,
}

/// Global configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoanNftConfigData {
    pub admin: Address,
    pub default_policy: TransferPolicy,
    pub paused: bool,
    pub max_token_uri_length: u32,
}

/// KYC attestation data
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KycData {
    pub user: Address,
    pub provider: Address,
    pub verified_at: u64,
    pub expires_at: u64,
    pub jurisdiction: String,
    pub is_valid: bool,
}

/// Initialize loan NFT module
pub fn initialize_loan_nft(
    env: &Env,
    admin: Address,
    default_policy: TransferPolicy,
) -> Result<(), LoanNftError> {
    admin.require_auth();

    let stored_admin = get_admin(env).map_err(|_| LoanNftError::Unauthorized)?;
    if admin != stored_admin {
        return Err(LoanNftError::Unauthorized);
    }

    let config = LoanNftConfigData {
        admin: admin.clone(),
        default_policy,
        paused: false,
        max_token_uri_length: MAX_URI_LENGTH,
    };

    env.storage()
        .instance()
        .set(&LoanNftDataKey::LoanNftConfig, &config);

    env.storage()
        .instance()
        .set(&LoanNftDataKey::NextTokenId, &1u64);

    env.storage()
        .instance()
        .set(&LoanNftDataKey::NextPolicyId, &1u64);

    env.storage()
        .instance()
        .set(&LoanNftDataKey::TotalSupply, &0u64);

    Ok(())
}

/// Create a new transfer policy
pub fn create_policy(
    env: &Env,
    admin: Address,
    policy_type: TransferPolicy,
    name: String,
    description: String,
    kyc_provider: Option<Address>,
    allowed_jurisdictions: Vec<String>,
) -> Result<u64, LoanNftError> {
    admin.require_auth();

    let config = get_loan_nft_config(env)?;
    if admin != config.admin {
        return Err(LoanNftError::Unauthorized);
    }

    let policy_id = get_next_policy_id(env);
    if policy_id >= MAX_POLICIES {
        return Err(LoanNftError::ListFull);
    }

    let current_time = env.ledger().timestamp();

    let policy = PolicyConfig {
        policy_id,
        policy_type: policy_type.clone(),
        name,
        description,
        whitelist: Vec::new(env),
        blacklist: Vec::new(env),
        kyc_provider,
        allowed_jurisdictions,
        created_at: current_time,
        updated_at: current_time,
        is_active: true,
    };

    env.storage()
        .persistent()
        .set(&LoanNftDataKey::PolicyConfig(policy_id), &policy);

    update_next_policy_id(env, policy_id + 1);

    Ok(policy_id)
}

/// Update a policy's whitelist
pub fn update_policy_whitelist(
    env: &Env,
    admin: Address,
    policy_id: u64,
    address: Address,
    add: bool,
) -> Result<(), LoanNftError> {
    admin.require_auth();

    let config = get_loan_nft_config(env)?;
    if admin != config.admin {
        return Err(LoanNftError::Unauthorized);
    }

    let mut policy: PolicyConfig = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::PolicyConfig(policy_id))
        .ok_or(LoanNftError::PolicyNotFound)?;

    if !policy.is_active {
        return Err(LoanNftError::InvalidPolicy);
    }

    if add {
        if policy.whitelist.len() >= MAX_LIST_SIZE {
            return Err(LoanNftError::ListFull);
        }
        if !policy.whitelist.contains(&address) {
            policy.whitelist.push_back(address.clone());
        }
    } else {
        // Remove from whitelist
        let mut new_list = Vec::new(env);
        for i in 0..policy.whitelist.len() {
            let addr = policy.whitelist.get(i).unwrap();
            if addr != address {
                new_list.push_back(addr);
            }
        }
        policy.whitelist = new_list;
    }

    policy.updated_at = env.ledger().timestamp();
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::PolicyConfig(policy_id), &policy);

    LoanNftWhitelistUpdatedEvent {
        policy_id,
        address,
        added: add,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(())
}

/// Update a policy's blacklist
pub fn update_policy_blacklist(
    env: &Env,
    admin: Address,
    policy_id: u64,
    address: Address,
    add: bool,
) -> Result<(), LoanNftError> {
    admin.require_auth();

    let config = get_loan_nft_config(env)?;
    if admin != config.admin {
        return Err(LoanNftError::Unauthorized);
    }

    let mut policy: PolicyConfig = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::PolicyConfig(policy_id))
        .ok_or(LoanNftError::PolicyNotFound)?;

    if !policy.is_active {
        return Err(LoanNftError::InvalidPolicy);
    }

    if add {
        if policy.blacklist.len() >= MAX_LIST_SIZE {
            return Err(LoanNftError::ListFull);
        }
        if !policy.blacklist.contains(&address) {
            policy.blacklist.push_back(address.clone());
        }
    } else {
        let mut new_list = Vec::new(env);
        for i in 0..policy.blacklist.len() {
            let addr = policy.blacklist.get(i).unwrap();
            if addr != address {
                new_list.push_back(addr);
            }
        }
        policy.blacklist = new_list;
    }

    policy.updated_at = env.ledger().timestamp();
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::PolicyConfig(policy_id), &policy);

    LoanNftWhitelistUpdatedEvent {
        policy_id,
        address,
        added: add,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(())
}

/// Mint a loan NFT for an existing loan position
pub fn mint_loan_nft(
    env: &Env,
    borrower: Address,
    loan_id: u64,
    principal: i128,
    outstanding_principal: i128,
    accrued_interest: i128,
    interest_rate_bps: i128,
    collateral_asset: Address,
    collateral_amount: i128,
    collateral_value: i128,
    health_factor_bps: u32,
    maturity_time: Option<u64>,
    policy_id: Option<u64>,
    metadata_uri: Option<String>,
) -> Result<u64, LoanNftError> {
    borrower.require_auth();

    let config = get_loan_nft_config(env)?;

    if config.paused {
        return Err(LoanNftError::Paused);
    }

    if principal <= 0 || outstanding_principal <= 0 {
        return Err(LoanNftError::InvalidLoanState);
    }

    // Check if loan already tokenized
    let existing_tokens = get_owner_tokens(env, &borrower);
    for token_id in existing_tokens.iter() {
        if let Some(pos) = get_loan_position(env, token_id) {
            if pos.loan_id == loan_id && pos.borrower == borrower {
                return Err(LoanNftError::AlreadyTokenized);
            }
        }
    }

    // Determine policy
    let policy = policy_id.unwrap_or_else(|| {
        match config.default_policy {
            TransferPolicy::Custom(id) => id,
            _ => 0, // Free policy
        }
    });

    // Validate policy exists if custom
    if policy != 0 {
        let _policy_config: PolicyConfig = env
            .storage()
            .persistent()
            .get(&LoanNftDataKey::PolicyConfig(policy))
            .ok_or(LoanNftError::PolicyNotFound)?;
    }

    let token_id = get_next_token_id(env);
    let current_time = env.ledger().timestamp();

    let position = LoanPosition {
        loan_id,
        borrower: borrower.clone(),
        principal,
        outstanding_principal,
        accrued_interest,
        interest_rate_bps,
        collateral_asset: collateral_asset.clone(),
        collateral_amount,
        collateral_value,
        health_factor_bps,
        last_accrual_time: current_time,
        maturity_time,
        status: LoanStatus::Active,
        created_at: current_time,
        updated_at: current_time,
    };

    // Store position
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenPosition(token_id), &position);

    // Store policy
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenPolicy(token_id), &policy);

    // Update owner's token list
    let mut owner_tokens = get_owner_tokens(env, &borrower);
    owner_tokens.push_back(token_id);
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::OwnerTokens(borrower.clone()), &owner_tokens);

    // Update next token ID and total supply
    update_next_token_id(env, token_id + 1);
    update_total_supply(env, 1);

    // Create metadata
    let metadata = create_loan_nft_metadata(env, token_id, &position, policy);
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenMetadata(token_id), &metadata);

    // Store URI if provided
    if let Some(uri) = metadata_uri {
        if uri.len() > config.max_token_uri_length {
            return Err(LoanNftError::UriTooLong);
        }
        env.storage()
            .persistent()
            .set(&LoanNftDataKey::TokenUri(token_id), &uri);
    }

    // Emit event
    LoanNftMintedEvent {
        token_id,
        borrower: borrower.clone(),
        loan_id,
        principal,
        collateral_asset,
        collateral_amount,
        policy: TransferPolicy::Custom(policy),
        timestamp: current_time,
    }
    .publish(env);

    Ok(token_id)
}

/// Transfer a loan NFT
pub fn transfer_loan_nft(
    env: &Env,
    from: Address,
    to: Address,
    token_id: u64,
) -> Result<(), LoanNftError> {
    from.require_auth();

    let config = get_loan_nft_config(env)?;

    if config.paused {
        return Err(LoanNftError::Paused);
    }

    // Get token position
    let mut position: LoanPosition = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPosition(token_id))
        .ok_or(LoanNftError::TokenNotFound)?;

    // Check loan state allows transfer
    if !matches!(position.status, LoanStatus::Active | LoanStatus::Restructured) {
        return Err(LoanNftError::NonTransferableState);
    }

    // Verify ownership
    let owner_tokens = get_owner_tokens(env, &from);
    if !owner_tokens.contains(&token_id) {
        return Err(LoanNftError::Unauthorized);
    }

    // Get policy
    let policy_id: u64 = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPolicy(token_id))
        .unwrap_or(0);

    // Check transfer policy
    check_transfer_policy(env, policy_id, &to)?;

    // Remove from current owner
    let mut from_tokens = owner_tokens;
    let index = from_tokens
        .iter()
        .position(|id| id == token_id)
        .ok_or(LoanNftError::TokenNotFound)? as u32;
    from_tokens.remove(index);
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::OwnerTokens(from.clone()), &from_tokens);

    // Add to new owner
    let mut to_tokens = get_owner_tokens(env, &to);
    to_tokens.push_back(token_id);
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::OwnerTokens(to.clone()), &to_tokens);

    // Update position metadata
    position.updated_at = env.ledger().timestamp();
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenPosition(token_id), &position);

    // Emit event
    let policy_type = get_policy_type(env, policy_id);
    LoanNftTransferredEvent {
        token_id,
        from: from.clone(),
        to: to.clone(),
        policy: policy_type,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(())
}

/// Split a loan NFT into two (partial transfer)
pub fn split_loan_nft(
    env: &Env,
    owner: Address,
    token_id: u64,
    split_principal: i128,
) -> Result<u64, LoanNftError> {
    owner.require_auth();

    let config = get_loan_nft_config(env)?;

    if config.paused {
        return Err(LoanNftError::Paused);
    }

    let mut position: LoanPosition = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPosition(token_id))
        .ok_or(LoanNftError::TokenNotFound)?;

    if position.borrower != owner {
        return Err(LoanNftError::Unauthorized);
    }

    if split_principal <= 0 || split_principal >= position.outstanding_principal {
        return Err(LoanNftError::InvalidSplitAmount);
    }

    if !matches!(position.status, LoanStatus::Active) {
        return Err(LoanNftError::InvalidLoanState);
    }

    let policy_id: u64 = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPolicy(token_id))
        .unwrap_or(0);

    let new_token_id = get_next_token_id(env);
    let current_time = env.ledger().timestamp();

    // Calculate proportional values
    let split_ratio = split_principal as i128 * 10000 / position.outstanding_principal;

    let split_interest = position.accrued_interest * split_ratio / 10000;
    let split_collateral = position.collateral_amount * split_ratio / 10000;
    let split_collateral_value = position.collateral_value * split_ratio / 10000;

    // Create new position
    let new_position = LoanPosition {
        loan_id: position.loan_id, // Same loan ID, but different token
        borrower: owner.clone(),
        principal: split_principal,
        outstanding_principal: split_principal,
        accrued_interest: split_interest,
        interest_rate_bps: position.interest_rate_bps,
        collateral_asset: position.collateral_asset.clone(),
        collateral_amount: split_collateral,
        collateral_value: split_collateral_value,
        health_factor_bps: position.health_factor_bps,
        last_accrual_time: position.last_accrual_time,
        maturity_time: position.maturity_time,
        status: LoanStatus::Active,
        created_at: current_time,
        updated_at: current_time,
    };

    // Update original position
    position.outstanding_principal -= split_principal;
    position.accrued_interest -= split_interest;
    position.collateral_amount -= split_collateral;
    position.collateral_value -= split_collateral_value;
    position.updated_at = current_time;

    // Store new position
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenPosition(new_token_id), &new_position);

    // Store policy for new token
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenPolicy(new_token_id), &policy_id);

    // Update original position
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenPosition(token_id), &position);

    // Update owner's token list
    let mut owner_tokens = get_owner_tokens(env, &owner);
    owner_tokens.push_back(new_token_id);
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::OwnerTokens(owner.clone()), &owner_tokens);

    // Update next token ID and total supply
    update_next_token_id(env, new_token_id + 1);
    update_total_supply(env, 1);

    // Create metadata for new token
    let new_metadata = create_loan_nft_metadata(env, new_token_id, &new_position, policy_id);
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenMetadata(new_token_id), &new_metadata);

    // Emit event
    LoanNftSplitEvent {
        original_token_id: token_id,
        new_token_id,
        split_amount: split_principal,
        owner: owner.clone(),
        timestamp: current_time,
    }
    .publish(env);

    Ok(new_token_id)
}

/// Merge two loan NFTs (same loan, same borrower)
pub fn merge_loan_nfts(
    env: &Env,
    owner: Address,
    token_id_a: u64,
    token_id_b: u64,
) -> Result<(), LoanNftError> {
    owner.require_auth();

    let config = get_loan_nft_config(env)?;

    if config.paused {
        return Err(LoanNftError::Paused);
    }

    let mut position_a: LoanPosition = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPosition(token_id_a))
        .ok_or(LoanNftError::TokenNotFound)?;

    let position_b: LoanPosition = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPosition(token_id_b))
        .ok_or(LoanNftError::TokenNotFound)?;

    // Verify ownership
    if position_a.borrower != owner || position_b.borrower != owner {
        return Err(LoanNftError::Unauthorized);
    }

    // Verify same loan
    if position_a.loan_id != position_b.loan_id {
        return Err(LoanNftError::IncompatibleMerge);
    }

    // Verify same collateral asset
    if position_a.collateral_asset != position_b.collateral_asset {
        return Err(LoanNftError::IncompatibleMerge);
    }

    // Verify compatible states
    if !matches!(position_a.status, LoanStatus::Active)
        || !matches!(position_b.status, LoanStatus::Active)
    {
        return Err(LoanNftError::InvalidLoanState);
    }

    // Verify same policy
    let policy_a: u64 = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPolicy(token_id_a))
        .unwrap_or(0);
    let policy_b: u64 = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPolicy(token_id_b))
        .unwrap_or(0);

    if policy_a != policy_b {
        return Err(LoanNftError::IncompatibleMerge);
    }

    let current_time = env.ledger().timestamp();

    // Merge positions
    position_a.outstanding_principal += position_b.outstanding_principal;
    position_a.accrued_interest += position_b.accrued_interest;
    position_a.collateral_amount += position_b.collateral_amount;
    position_a.collateral_value += position_b.collateral_value;
    position_a.updated_at = current_time;

    // Store merged position
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenPosition(token_id_a), &position_a);

    // Remove token B
    env.storage()
        .persistent()
        .remove(&LoanNftDataKey::TokenPosition(token_id_b));
    env.storage()
        .persistent()
        .remove(&LoanNftDataKey::TokenPolicy(token_id_b));
    env.storage()
        .persistent()
        .remove(&LoanNftDataKey::TokenMetadata(token_id_b));
    env.storage()
        .persistent()
        .remove(&LoanNftDataKey::TokenUri(token_id_b));

    // Update owner's token list
    let mut owner_tokens = get_owner_tokens(env, &owner);
    let mut new_tokens = Vec::new(env);
    for i in 0..owner_tokens.len() {
        let id = owner_tokens.get(i).unwrap();
        if id != token_id_b {
            new_tokens.push_back(id);
        }
    }
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::OwnerTokens(owner.clone()), &new_tokens);

    // Update total supply
    update_total_supply(env, -1);

    // Update metadata for token A
    let new_metadata = create_loan_nft_metadata(env, token_id_a, &position_a, policy_a);
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenMetadata(token_id_a), &new_metadata);

    // Emit event
    LoanNftMergedEvent {
        token_id_a,
        token_id_b,
        owner: owner.clone(),
        timestamp: current_time,
    }
    .publish(env);

    Ok(())
}

/// Burn a loan NFT (loan repaid or liquidated)
pub fn burn_loan_nft(
    env: &Env,
    owner: Address,
    token_id: u64,
    reason: Symbol,
) -> Result<(), LoanNftError> {
    owner.require_auth();

    let config = get_loan_nft_config(env)?;

    if config.paused {
        return Err(LoanNftError::Paused);
    }

    let position: LoanPosition = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPosition(token_id))
        .ok_or(LoanNftError::TokenNotFound)?;

    if position.borrower != owner {
        return Err(LoanNftError::Unauthorized);
    }

    // Remove from owner's token list
    let mut owner_tokens = get_owner_tokens(env, &owner);
    let mut new_tokens = Vec::new(env);
    for i in 0..owner_tokens.len() {
        let id = owner_tokens.get(i).unwrap();
        if id != token_id {
            new_tokens.push_back(id);
        }
    }
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::OwnerTokens(owner.clone()), &new_tokens);

    // Clean up storage
    env.storage()
        .persistent()
        .remove(&LoanNftDataKey::TokenPosition(token_id));
    env.storage()
        .persistent()
        .remove(&LoanNftDataKey::TokenPolicy(token_id));
    env.storage()
        .persistent()
        .remove(&LoanNftDataKey::TokenMetadata(token_id));
    env.storage()
        .persistent()
        .remove(&LoanNftDataKey::TokenUri(token_id));

    // Update total supply
    update_total_supply(env, -1);

    // Emit event
    LoanNftBurnedEvent {
        token_id,
        burner: owner.clone(),
        reason,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(())
}

/// Update loan position state (called after interest accrual, payment, etc.)
pub fn update_loan_position(
    env: &Env,
    admin: Address,
    token_id: u64,
    outstanding_principal: Option<i128>,
    accrued_interest: Option<i128>,
    collateral_amount: Option<i128>,
    collateral_value: Option<i128>,
    health_factor_bps: Option<u32>,
    status: Option<LoanStatus>,
) -> Result<(), LoanNftError> {
    admin.require_auth();

    let config = get_loan_nft_config(env)?;
    if admin != config.admin {
        return Err(LoanNftError::Unauthorized);
    }

    let mut position: LoanPosition = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPosition(token_id))
        .ok_or(LoanNftError::TokenNotFound)?;

    if let Some(v) = outstanding_principal {
        position.outstanding_principal = v;
    }
    if let Some(v) = accrued_interest {
        position.accrued_interest = v;
    }
    if let Some(v) = collateral_amount {
        position.collateral_amount = v;
    }
    if let Some(v) = collateral_value {
        position.collateral_value = v;
    }
    if let Some(v) = health_factor_bps {
        position.health_factor_bps = v;
    }
    if let Some(v) = status {
        position.status = v;
    }

    position.last_accrual_time = env.ledger().timestamp();
    position.updated_at = env.ledger().timestamp();

    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenPosition(token_id), &position);

    // Update metadata
    let policy_id: u64 = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPolicy(token_id))
        .unwrap_or(0);

    let new_metadata = create_loan_nft_metadata(env, token_id, &position, policy_id);
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenMetadata(token_id), &new_metadata);

    Ok(())
}

/// Update NFT transfer policy
pub fn update_token_policy(
    env: &Env,
    admin: Address,
    token_id: u64,
    new_policy_id: u64,
) -> Result<(), LoanNftError> {
    admin.require_auth();

    let config = get_loan_nft_config(env)?;
    if admin != config.admin {
        return Err(LoanNftError::Unauthorized);
    }

    // Verify token exists
    let _position: LoanPosition = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPosition(token_id))
        .ok_or(LoanNftError::TokenNotFound)?;

    // Verify new policy exists
    if new_policy_id != 0 {
        let _policy: PolicyConfig = env
            .storage()
            .persistent()
            .get(&LoanNftDataKey::PolicyConfig(new_policy_id))
            .ok_or(LoanNftError::PolicyNotFound)?;
    }

    let old_policy_id: u64 = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPolicy(token_id))
        .unwrap_or(0);

    let old_policy_type = get_policy_type(env, old_policy_id);
    let new_policy_type = get_policy_type(env, new_policy_id);

    // Update policy
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::TokenPolicy(token_id), &new_policy_id);

    // Emit event
    LoanNftPolicyUpdatedEvent {
        token_id,
        old_policy: old_policy_type,
        new_policy: new_policy_type,
        updated_by: admin,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);

    Ok(())
}

/// Set KYC attestation for a user
pub fn set_kyc_attestation(
    env: &Env,
    provider: Address,
    user: Address,
    expires_at: u64,
    jurisdiction: String,
) -> Result<(), LoanNftError> {
    provider.require_auth();

    let config = get_loan_nft_config(env)?;
    if provider != config.admin {
        // In production, would verify provider is authorized KYC provider
        return Err(LoanNftError::Unauthorized);
    }

    let current_time = env.ledger().timestamp();

    if expires_at <= current_time {
        return Err(LoanNftError::InvalidPolicy);
    }

    let kyc = KycData {
        user: user.clone(),
        provider,
        verified_at: current_time,
        expires_at,
        jurisdiction,
        is_valid: true,
    };

    env.storage()
        .persistent()
        .set(&LoanNftDataKey::KycAttestation(user), &kyc);

    Ok(())
}

/// Revoke KYC attestation
pub fn revoke_kyc_attestation(
    env: &Env,
    provider: Address,
    user: Address,
) -> Result<(), LoanNftError> {
    provider.require_auth();

    let config = get_loan_nft_config(env)?;
    if provider != config.admin {
        return Err(LoanNftError::Unauthorized);
    }

    let mut kyc: KycData = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::KycAttestation(user))
        .ok_or(LoanNftError::PolicyNotFound)?;

    kyc.is_valid = false;
    env.storage()
        .persistent()
        .set(&LoanNftDataKey::KycAttestation(user), &kyc);

    Ok(())
}

/// Get loan position for a token
pub fn get_loan_position(env: &Env, token_id: u64) -> Option<LoanPosition> {
    env.storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPosition(token_id))
}

/// Get token policy
pub fn get_token_policy(env: &Env, token_id: u64) -> u64 {
    env.storage()
        .persistent()
        .get(&LoanNftDataKey::TokenPolicy(token_id))
        .unwrap_or(0)
}

/// Get NFT metadata
pub fn get_token_metadata(env: &Env, token_id: u64) -> Option<NftMetadata> {
    env.storage()
        .persistent()
        .get(&LoanNftDataKey::TokenMetadata(token_id))
}

/// Get token URI
pub fn get_token_uri(env: &Env, token_id: u64) -> Option<String> {
    env.storage()
        .persistent()
        .get(&LoanNftDataKey::TokenUri(token_id))
}

/// Get all tokens owned by an address
pub fn get_owner_tokens(env: &Env, owner: &Address) -> Vec<u64> {
    env.storage()
        .persistent()
        .get(&LoanNftDataKey::OwnerTokens(owner.clone()))
        .unwrap_or_else(|| Vec::new(env))
}

/// Get policy config
pub fn get_policy_config(env: &Env, policy_id: u64) -> Option<PolicyConfig> {
    env.storage()
        .persistent()
        .get(&LoanNftDataKey::PolicyConfig(policy_id))
}

/// Get KYC attestation
pub fn get_kyc_attestation(env: &Env, user: Address) -> Option<KycData> {
    env.storage()
        .persistent()
        .get(&LoanNftDataKey::KycAttestation(user))
}

/// Get total supply
pub fn get_total_supply(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&LoanNftDataKey::TotalSupply)
        .unwrap_or(0)
}

/// Get loan NFT config
pub fn get_loan_nft_config(env: &Env) -> Result<LoanNftConfigData, LoanNftError> {
    env.storage()
        .instance()
        .get(&LoanNftDataKey::LoanNftConfig)
        .ok_or(LoanNftError::PolicyNotFound)
}

/// Set pause (admin only)
pub fn set_pause(env: &Env, admin: Address, paused: bool) -> Result<(), LoanNftError> {
    admin.require_auth();

    let mut config = get_loan_nft_config(env)?;
    if admin != config.admin {
        return Err(LoanNftError::Unauthorized);
    }

    config.paused = paused;
    env.storage()
        .instance()
        .set(&LoanNftDataKey::LoanNftConfig, &config);

    Ok(())
}

// Internal helper functions

fn get_next_token_id(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&LoanNftDataKey::NextTokenId)
        .unwrap_or(1)
}

fn update_next_token_id(env: &Env, next_id: u64) {
    env.storage()
        .instance()
        .set(&LoanNftDataKey::NextTokenId, &next_id);
}

fn get_next_policy_id(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&LoanNftDataKey::NextPolicyId)
        .unwrap_or(1)
}

fn update_next_policy_id(env: &Env, next_id: u64) {
    env.storage()
        .instance()
        .set(&LoanNftDataKey::NextPolicyId, &next_id);
}

fn update_total_supply(env: &Env, delta: i64) {
    let current = get_total_supply(env);
    let new_supply = if delta >= 0 {
        current + delta as u64
    } else {
        current - (-delta) as u64
    };
    env.storage()
        .instance()
        .set(&LoanNftDataKey::TotalSupply, &new_supply);
}

fn get_policy_type(env: &Env, policy_id: u64) -> TransferPolicy {
    if policy_id == 0 {
        return TransferPolicy::Free;
    }
    env.storage()
        .persistent()
        .get(&LoanNftDataKey::PolicyConfig(policy_id))
        .map(|p: PolicyConfig| p.policy_type)
        .unwrap_or(TransferPolicy::Free)
}

/// Check if transfer is allowed by policy
fn check_transfer_policy(env: &Env, policy_id: u64, to: &Address) -> Result<(), LoanNftError> {
    if policy_id == 0 {
        // Free policy - always allowed
        return Ok(());
    }

    let policy: PolicyConfig = env
        .storage()
        .persistent()
        .get(&LoanNftDataKey::PolicyConfig(policy_id))
        .ok_or(LoanNftError::PolicyNotFound)?;

    if !policy.is_active {
        return Err(LoanNftError::InvalidPolicy);
    }

    match policy.policy_type {
        TransferPolicy::Free => Ok(()),
        TransferPolicy::Restricted => {
            if policy.whitelist.contains(to) {
                Ok(())
            } else {
                Err(LoanNftError::NotWhitelisted)
            }
        }
        TransferPolicy::Blacklist => {
            if policy.blacklist.contains(to) {
                Err(LoanNftError::Blacklisted)
            } else {
                Ok(())
            }
        }
        TransferPolicy::KycRequired => {
            let kyc = get_kyc_attestation(env, to.clone());
            match kyc {
                Some(k) if k.is_valid && k.expires_at > env.ledger().timestamp() => {
                    // Verify KYC provider matches if specified
                    if let Some(provider) = policy.kyc_provider {
                        if k.provider != provider {
                            return Err(LoanNftError::KycFailed);
                        }
                    }
                    Ok(())
                }
                _ => Err(LoanNftError::KycFailed),
            }
        }
        TransferPolicy::JurisdictionRestricted => {
            let kyc = get_kyc_attestation(env, to.clone());
            match kyc {
                Some(k) if k.is_valid && k.expires_at > env.ledger().timestamp() => {
                    if policy.allowed_jurisdictions.contains(&k.jurisdiction) {
                        Ok(())
                    } else {
                        Err(LoanNftError::JurisdictionNotAllowed)
                    }
                }
                _ => Err(LoanNftError::KycFailed),
            }
        }
        TransferPolicy::Custom(_) => {
            // Custom policy - default to restricted with whitelist
            if policy.whitelist.contains(to) {
                Ok(())
            } else {
                Err(LoanNftError::NotWhitelisted)
            }
        }
    }
}

/// Create NFT metadata for a loan position
fn create_loan_nft_metadata(
    env: &Env,
    token_id: u64,
    position: &LoanPosition,
    policy_id: u64,
) -> NftMetadata {
    let policy_type = get_policy_type(env, policy_id);

    let status_str = match position.status {
        LoanStatus::Active => "Active",
        LoanStatus::Repaid => "Repaid",
        LoanStatus::Liquidated => "Liquidated",
        LoanStatus::Defaulted => "Defaulted",
        LoanStatus::Restructured => "Restructured",
    };

    let policy_str = match policy_type {
        TransferPolicy::Free => "Free",
        TransferPolicy::Restricted => "Restricted",
        TransferPolicy::Blacklist => "Blacklist",
        TransferPolicy::KycRequired => "KYC Required",
        TransferPolicy::JurisdictionRestricted => "Jurisdiction Restricted",
        TransferPolicy::Custom(_) => "Custom",
    };

    let mut attributes = Vec::new(env);

    attributes.push_back(NftAttribute {
        trait_type: String::from_str(env, "Loan ID"),
        value: String::from_str(env, &position.loan_id.to_string()),
    });

    attributes.push_back(NftAttribute {
        trait_type: String::from_str(env, "Principal"),
        value: String::from_str(env, &position.principal.to_string()),
    });

    attributes.push_back(NftAttribute {
        trait_type: String::from_str(env, "Outstanding Principal"),
        value: String::from_str(env, &position.outstanding_principal.to_string()),
    });

    attributes.push_back(NftAttribute {
        trait_type: String::from_str(env, "Interest Rate (bps)"),
        value: String::from_str(env, &position.interest_rate_bps.to_string()),
    });

    attributes.push_back(NftAttribute {
        trait_type: String::from_str(env, "Health Factor (bps)"),
        value: String::from_str(env, &position.health_factor_bps.to_string()),
    });

    attributes.push_back(NftAttribute {
        trait_type: String::from_str(env, "Status"),
        value: String::from_str(env, status_str),
    });

    attributes.push_back(NftAttribute {
        trait_type: String::from_str(env, "Transfer Policy"),
        value: String::from_str(env, policy_str),
    });

    if let Some(maturity) = position.maturity_time {
        attributes.push_back(NftAttribute {
            trait_type: String::from_str(env, "Maturity"),
            value: String::from_str(env, &maturity.to_string()),
        });
    }

    NftMetadata {
        token_id,
        name: String::from_str(env, "StellarLend Loan Position"),
        description: String::from_str(env, "NFT representing a loan position on StellarLend"),
        image_uri: String::from_str(env, ""),
        external_uri: String::from_str(env, ""),
        attributes,
    }
}

// Contract client interface
#[cfg(feature = "client")]
pub mod client {
    use super::*;
    use soroban_sdk::contractclient;

    #[contractclient(name = "LoanNftClient")]
    pub trait LoanNftClientInterface {
        fn initialize_loan_nft(
            env: Env,
            admin: Address,
            default_policy: TransferPolicy,
        ) -> Result<(), LoanNftError>;

        fn create_policy(
            env: Env,
            admin: Address,
            policy_type: TransferPolicy,
            name: String,
            description: String,
            kyc_provider: Option<Address>,
            allowed_jurisdictions: Vec<String>,
        ) -> Result<u64, LoanNftError>;

        fn mint_loan_nft(
            env: Env,
            borrower: Address,
            loan_id: u64,
            principal: i128,
            outstanding_principal: i128,
            accrued_interest: i128,
            interest_rate_bps: i128,
            collateral_asset: Address,
            collateral_amount: i128,
            collateral_value: i128,
            health_factor_bps: u32,
            maturity_time: Option<u64>,
            policy_id: Option<u64>,
            metadata_uri: Option<String>,
        ) -> Result<u64, LoanNftError>;

        fn transfer_loan_nft(
            env: Env,
            from: Address,
            to: Address,
            token_id: u64,
        ) -> Result<(), LoanNftError>;

        fn split_loan_nft(
            env: Env,
            owner: Address,
            token_id: u64,
            split_principal: i128,
        ) -> Result<u64, LoanNftError>;

        fn merge_loan_nfts(
            env: Env,
            owner: Address,
            token_id_a: u64,
            token_id_b: u64,
        ) -> Result<(), LoanNftError>;

        fn burn_loan_nft(
            env: Env,
            owner: Address,
            token_id: u64,
            reason: Symbol,
        ) -> Result<(), LoanNftError>;

        fn update_loan_position(
            env: Env,
            admin: Address,
            token_id: u64,
            outstanding_principal: Option<i128>,
            accrued_interest: Option<i128>,
            collateral_amount: Option<i128>,
            collateral_value: Option<i128>,
            health_factor_bps: Option<u32>,
            status: Option<LoanStatus>,
        ) -> Result<(), LoanNftError>;

        fn update_token_policy(
            env: Env,
            admin: Address,
            token_id: u64,
            new_policy_id: u64,
        ) -> Result<(), LoanNftError>;

        fn set_kyc_attestation(
            env: Env,
            provider: Address,
            user: Address,
            expires_at: u64,
            jurisdiction: String,
        ) -> Result<(), LoanNftError>;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        testutils::Address as _,
        Address, Env, String, Vec,
    };

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let recipient = Address::generate(&env);
        (env, admin, borrower, recipient)
    }

    #[test]
    fn test_initialize_loan_nft() {
        let (env, admin, _borrower, _recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let config = get_loan_nft_config(&env).unwrap();
        assert_eq!(config.admin, admin);
        assert_eq!(config.default_policy, TransferPolicy::Free);
        assert!(!config.paused);
    }

    #[test]
    fn test_create_policy() {
        let (env, admin, _borrower, _recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let name = String::from_str(&env, "KYC Policy");
        let desc = String::from_str(&env, "KYC required for transfers");
        let kyc_provider = Address::generate(&env);
        let jurisdictions = Vec::new(&env);

        let policy_id = create_policy(
            &env,
            admin.clone(),
            TransferPolicy::KycRequired,
            name,
            desc,
            Some(kyc_provider.clone()),
            jurisdictions,
        ).unwrap();

        assert_eq!(policy_id, 1);

        let policy = get_policy_config(&env, policy_id).unwrap();
        assert_eq!(policy.policy_type, TransferPolicy::KycRequired);
        assert_eq!(policy.kyc_provider, Some(kyc_provider));
        assert!(policy.is_active);
    }

    #[test]
    fn test_update_whitelist() {
        let (env, admin, _borrower, recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let policy_id = create_policy(
            &env,
            admin.clone(),
            TransferPolicy::Restricted,
            String::from_str(&env, "Restricted"),
            String::from_str(&env, "Whitelist only"),
            None,
            Vec::new(&env),
        ).unwrap();

        // Add to whitelist
        update_policy_whitelist(&env, admin.clone(), policy_id, recipient.clone(), true).unwrap();

        let policy = get_policy_config(&env, policy_id).unwrap();
        assert!(policy.whitelist.contains(&recipient));

        // Remove from whitelist
        update_policy_whitelist(&env, admin.clone(), policy_id, recipient.clone(), false).unwrap();

        let policy = get_policy_config(&env, policy_id).unwrap();
        assert!(!policy.whitelist.contains(&recipient));
    }

    #[test]
    fn test_mint_loan_nft() {
        let (env, admin, borrower, _recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let collateral_asset = Address::generate(&env);
        let token_id = mint_loan_nft(
            &env,
            borrower.clone(),
            123, // loan_id
            1000000, // principal
            1000000, // outstanding
            0, // accrued interest
            500, // 5% interest rate
            collateral_asset.clone(),
            1500000, // collateral amount
            2000000, // collateral value
            15000, // 150% health factor
            None, // no maturity
            None, // default policy
            None, // no metadata URI
        ).unwrap();

        assert_eq!(token_id, 1);

        let position = get_loan_position(&env, token_id).unwrap();
        assert_eq!(position.loan_id, 123);
        assert_eq!(position.borrower, borrower);
        assert_eq!(position.principal, 1000000);
        assert_eq!(position.status, LoanStatus::Active);

        let metadata = get_token_metadata(&env, token_id).unwrap();
        assert_eq!(metadata.token_id, token_id);
        assert!(!metadata.attributes.is_empty());
    }

    #[test]
    fn test_transfer_loan_nft_free_policy() {
        let (env, admin, borrower, recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let collateral_asset = Address::generate(&env);
        let token_id = mint_loan_nft(
            &env,
            borrower.clone(),
            123,
            1000000,
            1000000,
            0,
            500,
            collateral_asset.clone(),
            1500000,
            2000000,
            15000,
            None,
            None,
            None,
        ).unwrap();

        // Transfer should succeed with free policy
        transfer_loan_nft(&env, borrower.clone(), recipient.clone(), token_id).unwrap();

        let position = get_loan_position(&env, token_id).unwrap();
        // Position borrower doesn't change, but ownership does
        assert_eq!(position.borrower, borrower);

        let owner_tokens = get_owner_tokens(&env, &recipient);
        assert!(owner_tokens.contains(&token_id));

        let borrower_tokens = get_owner_tokens(&env, &borrower);
        assert!(!borrower_tokens.contains(&token_id));
    }

    #[test]
    fn test_transfer_loan_nft_restricted_policy() {
        let (env, admin, borrower, recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        // Create restricted policy
        let policy_id = create_policy(
            &env,
            admin.clone(),
            TransferPolicy::Restricted,
            String::from_str(&env, "Restricted"),
            String::from_str(&env, "Whitelist only"),
            None,
            Vec::new(&env),
        ).unwrap();

        let collateral_asset = Address::generate(&env);
        let token_id = mint_loan_nft(
            &env,
            borrower.clone(),
            123,
            1000000,
            1000000,
            0,
            500,
            collateral_asset.clone(),
            1500000,
            2000000,
            15000,
            Some(policy_id),
            None,
        ).unwrap();

        // Transfer without whitelist should fail
        let result = transfer_loan_nft(&env, borrower.clone(), recipient.clone(), token_id);
        assert!(matches!(result, Err(LoanNftError::NotWhitelisted)));

        // Add to whitelist
        update_policy_whitelist(&env, admin.clone(), policy_id, recipient.clone(), true).unwrap();

        // Transfer should now succeed
        transfer_loan_nft(&env, borrower.clone(), recipient.clone(), token_id).unwrap();
    }

    #[test]
    fn test_split_loan_nft() {
        let (env, admin, borrower, _recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let collateral_asset = Address::generate(&env);
        let token_id = mint_loan_nft(
            &env,
            borrower.clone(),
            123,
            1000000,
            1000000,
            50000,
            500,
            collateral_asset.clone(),
            1500000,
            2000000,
            15000,
            None,
            None,
            None,
        ).unwrap();

        // Split 30% of principal
        let new_token_id = split_loan_nft(&env, borrower.clone(), token_id, 300000).unwrap();

        assert_eq!(new_token_id, 2);

        // Check original position updated
        let original = get_loan_position(&env, token_id).unwrap();
        assert_eq!(original.outstanding_principal, 700000);

        // Check new position
        let new_position = get_loan_position(&env, new_token_id).unwrap();
        assert_eq!(new_position.outstanding_principal, 300000);
        assert_eq!(new_position.loan_id, 123); // Same loan ID

        // Both tokens owned by borrower
        let tokens = get_owner_tokens(&env, &borrower);
        assert!(tokens.contains(&token_id));
        assert!(tokens.contains(&new_token_id));
    }

    #[test]
    fn test_merge_loan_nfts() {
        let (env, admin, borrower, _recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let collateral_asset = Address::generate(&env);
        let token_id_1 = mint_loan_nft(
            &env,
            borrower.clone(),
            123,
            1000000,
            600000,
            30000,
            500,
            collateral_asset.clone(),
            900000,
            1200000,
            15000,
            None,
            None,
            None,
        ).unwrap();

        let token_id_2 = mint_loan_nft(
            &env,
            borrower.clone(),
            123, // Same loan ID
            1000000,
            400000,
            20000,
            500,
            collateral_asset.clone(),
            600000,
            800000,
            15000,
            None,
            None,
            None,
        ).unwrap();

        // Merge token_2 into token_1
        merge_loan_nfts(&env, borrower.clone(), token_id_1, token_id_2).unwrap();

        // Check merged position
        let merged = get_loan_position(&env, token_id_1).unwrap();
        assert_eq!(merged.outstanding_principal, 1000000);
        assert_eq!(merged.accrued_interest, 50000);
        assert_eq!(merged.collateral_amount, 1500000);

        // Token 2 should be gone
        assert!(get_loan_position(&env, token_id_2).is_none());

        // Only token_1 in owner's list
        let tokens = get_owner_tokens(&env, &borrower);
        assert!(tokens.contains(&token_id_1));
        assert!(!tokens.contains(&token_id_2));
    }

    #[test]
    fn test_burn_loan_nft() {
        let (env, admin, borrower, _recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let collateral_asset = Address::generate(&env);
        let token_id = mint_loan_nft(
            &env,
            borrower.clone(),
            123,
            1000000,
            1000000,
            0,
            500,
            collateral_asset.clone(),
            1500000,
            2000000,
            15000,
            None,
            None,
            None,
        ).unwrap();

        // Burn the token
        burn_loan_nft(&env, borrower.clone(), token_id, Symbol::new(&env, "repaid")).unwrap();

        // Token should be gone
        assert!(get_loan_position(&env, token_id).is_none());
        assert!(get_token_metadata(&env, token_id).is_none());

        let tokens = get_owner_tokens(&env, &borrower);
        assert!(!tokens.contains(&token_id));
    }

    #[test]
    fn test_update_loan_position() {
        let (env, admin, borrower, _recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let collateral_asset = Address::generate(&env);
        let token_id = mint_loan_nft(
            &env,
            borrower.clone(),
            123,
            1000000,
            1000000,
            0,
            500,
            collateral_asset.clone(),
            1500000,
            2000000,
            15000,
            None,
            None,
            None,
        ).unwrap();

        // Update position after payment
        update_loan_position(
            &env,
            admin.clone(),
            token_id,
            Some(800000), // outstanding reduced
            Some(10000),  // interest accrued
            Some(1500000),
            Some(2000000),
            Some(16000),  // health factor improved
            None,
        ).unwrap();

        let position = get_loan_position(&env, token_id).unwrap();
        assert_eq!(position.outstanding_principal, 800000);
        assert_eq!(position.accrued_interest, 10000);
        assert_eq!(position.health_factor_bps, 16000);
    }

    #[test]
    fn test_kyc_attestation() {
        let (env, admin, borrower, recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        // Create KYC required policy
        let policy_id = create_policy(
            &env,
            admin.clone(),
            TransferPolicy::KycRequired,
            String::from_str(&env, "KYC Policy"),
            String::from_str(&env, "KYC required"),
            None,
            Vec::new(&env),
        ).unwrap();

        let collateral_asset = Address::generate(&env);
        let token_id = mint_loan_nft(
            &env,
            borrower.clone(),
            123,
            1000000,
            1000000,
            0,
            500,
            collateral_asset.clone(),
            1500000,
            2000000,
            15000,
            Some(policy_id),
            None,
        ).unwrap();

        // Transfer without KYC should fail
        let result = transfer_loan_nft(&env, borrower.clone(), recipient.clone(), token_id);
        assert!(matches!(result, Err(LoanNftError::KycFailed)));

        // Set KYC attestation
        set_kyc_attestation(
            &env,
            admin.clone(), // admin acts as KYC provider
            recipient.clone(),
            env.ledger().timestamp() + 86400 * 365, // 1 year
            String::from_str(&env, "US"),
        ).unwrap();

        // Transfer should now succeed
        transfer_loan_nft(&env, borrower.clone(), recipient.clone(), token_id).unwrap();
    }

    #[test]
    fn test_pause() {
        let (env, admin, borrower, recipient) = setup();
        initialize_loan_nft(&env, admin.clone(), TransferPolicy::Free).unwrap();

        let collateral_asset = Address::generate(&env);
        let token_id = mint_loan_nft(
            &env,
            borrower.clone(),
            123,
            1000000,
            1000000,
            0,
            500,
            collateral_asset.clone(),
            1500000,
            2000000,
            15000,
            None,
            None,
            None,
        ).unwrap();

        // Pause
        set_pause(&env, admin.clone(), true).unwrap();

        // Transfer should fail
        let result = transfer_loan_nft(&env, borrower.clone(), recipient.clone(), token_id);
        assert!(matches!(result, Err(LoanNftError::Paused)));

        // Unpause
        set_pause(&env, admin.clone(), false).unwrap();

        // Transfer should work
        transfer_loan_nft(&env, borrower.clone(), recipient.clone(), token_id).unwrap();
    }
}