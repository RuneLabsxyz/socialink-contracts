use starknet::ContractAddress;
use starknet::{contract_address_const};

use snforge_std::{declare, ContractClassTrait, start_cheat_caller_address};

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

fn VERIFIED_ADDRESS() -> ContractAddress {
    contract_address_const::<'VERIFIED_ADDRESS'>()
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
fn test_increase_balance() {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();

    let contract_address = deploy_contract("Auth", OWNER().into(), key_pair.public_key);
    let dispatcher = IAuthDispatcher { contract_address };

    let (r, s): (felt252, felt252) = key_pair.sign(VERIFIED_ADDRESS().into()).unwrap();

    start_cheat_caller_address(dispatcher.contract_address, VERIFIED_ADDRESS());

    dispatcher.add_authorized_with_signature(array![r, s]);

    let can_take_action = dispatcher.can_take_action(VERIFIED_ADDRESS());

    assert(can_take_action, 'Should be able to take action');
}



