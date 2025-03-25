use starknet::ContractAddress;
use starknet::{contract_address_const, get_block_timestamp};

use snforge_std::{
    declare, ContractClassTrait, start_cheat_caller_address, start_cheat_block_timestamp_global
};

use snforge_std::signature::KeyPairTrait;
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl
};

use openzeppelin::utils::serde::SerializedAppend;
// use core::starknet::SyscallResultTrait;

use social_link_contracts::auth::{IAuthDispatcher, IAuthDispatcherTrait};

fn OWNER() -> ContractAddress {
    contract_address_const::<'OWNER'>()
}

fn AUTHORIZED_ADDRESS() -> ContractAddress {
    contract_address_const::<'AUTHORIZED_ADDRESS'>()
}

fn NEW_VERIFIER_ADDRESS() -> ContractAddress {
    contract_address_const::<'NEW_VERIFIER'>()
}

fn deploy_contract(name: ByteArray, owner: felt252, verifier: felt252) -> ContractAddress {
    let contract = declare(name).unwrap();
    let mut calldata = array![];
    calldata.append_serde(owner);
    calldata.append_serde(verifier);
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

#[test]
fn test_add_authorized_with_signature() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };
    let (r, s): (felt252, felt252) = key_pair.sign(AUTHORIZED_ADDRESS().into()).unwrap();

    start_cheat_caller_address(dispatcher.contract_address, AUTHORIZED_ADDRESS());
    dispatcher.add_authorized_with_signature(array![r, s]);

    let can_take_action = dispatcher.can_take_action(AUTHORIZED_ADDRESS());
    assert(can_take_action, 'Should be able to take action');
}

#[test]
fn test_add_authorized() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };

    start_cheat_caller_address(dispatcher.contract_address, OWNER());
    dispatcher.add_authorized(AUTHORIZED_ADDRESS());

    let can_take_action = dispatcher.can_take_action(AUTHORIZED_ADDRESS());
    assert(can_take_action, 'Should be able to take action');
}

#[test]
fn test_remove_authorized() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };

    start_cheat_caller_address(dispatcher.contract_address, OWNER());
    dispatcher.add_authorized(AUTHORIZED_ADDRESS());
    assert(dispatcher.can_take_action(AUTHORIZED_ADDRESS()), 'Should be able to take action');

    dispatcher.remove_authorized(AUTHORIZED_ADDRESS());
    let can_take_action = dispatcher.can_take_action(AUTHORIZED_ADDRESS());
    assert(!can_take_action, 'Should not take action');
}

#[test]
fn test_set_verifier() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };

    start_cheat_caller_address(dispatcher.contract_address, OWNER());

    let key_pair_new_verifier = KeyPairTrait::<felt252, felt252>::generate();
    dispatcher.set_verifier(key_pair_new_verifier.public_key);
    let (r, s): (felt252, felt252) = key_pair_new_verifier
        .sign(AUTHORIZED_ADDRESS().into())
        .unwrap();

    start_cheat_caller_address(dispatcher.contract_address, AUTHORIZED_ADDRESS());
    dispatcher.add_authorized_with_signature(array![r, s]);

    assert(dispatcher.can_take_action(AUTHORIZED_ADDRESS()), 'Should be able to take action');
}

#[test]
fn test_add_verifier_account() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };

    start_cheat_caller_address(dispatcher.contract_address, OWNER());
    dispatcher.add_verifier(NEW_VERIFIER_ADDRESS());

    start_cheat_caller_address(dispatcher.contract_address, NEW_VERIFIER_ADDRESS());
    dispatcher.add_authorized(AUTHORIZED_ADDRESS());

    assert(dispatcher.can_take_action(AUTHORIZED_ADDRESS()), 'Verifier should be authorized');
}

#[test]
#[should_panic()]
fn test_remove_verifier() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };

    start_cheat_caller_address(dispatcher.contract_address, OWNER());
    dispatcher.add_verifier(NEW_VERIFIER_ADDRESS());

    start_cheat_caller_address(dispatcher.contract_address, NEW_VERIFIER_ADDRESS());
    dispatcher.add_authorized(AUTHORIZED_ADDRESS());
    assert(dispatcher.can_take_action(AUTHORIZED_ADDRESS()), 'be authorized');

    start_cheat_caller_address(dispatcher.contract_address, OWNER());
    dispatcher.remove_verifier(NEW_VERIFIER_ADDRESS());

    start_cheat_caller_address(dispatcher.contract_address, NEW_VERIFIER_ADDRESS());
    dispatcher.add_authorized(AUTHORIZED_ADDRESS());
}

#[test]
fn test_lock_and_unlock_actions() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };

    start_cheat_caller_address(dispatcher.contract_address, OWNER());
    dispatcher.add_authorized(AUTHORIZED_ADDRESS());

    dispatcher.lock_actions();
    assert(!dispatcher.can_take_action(AUTHORIZED_ADDRESS()), 'Actions should be locked');

    dispatcher.unlock_actions();
    assert(dispatcher.can_take_action(AUTHORIZED_ADDRESS()), 'Actions should be unlocked');
}

#[test]
fn test_get_owner() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };

    let owner = dispatcher.get_owner();
    assert(owner == OWNER(), 'Owner should match');
}


#[test]
fn test_expiration() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };

    // Add an authorized address
    start_cheat_caller_address(dispatcher.contract_address, OWNER());
    dispatcher.add_authorized(AUTHORIZED_ADDRESS());
    assert(dispatcher.can_take_action(AUTHORIZED_ADDRESS()), 'Should be able to take action');

    // Set expiration to current timestamp + 100
    let current_timestamp = get_block_timestamp();
    dispatcher.set_expiration(current_timestamp + 100);
    assert(dispatcher.get_expiration() == current_timestamp + 100, 'Expiration not set correctly');

    // Actions should still work before expiration
    assert(dispatcher.can_take_action(AUTHORIZED_ADDRESS()), 'Should be able to take action');

    // Advance time past expiration
    start_cheat_block_timestamp_global(current_timestamp + 101);
    assert(!dispatcher.can_take_action(AUTHORIZED_ADDRESS()), 'time expiration reached');
}
