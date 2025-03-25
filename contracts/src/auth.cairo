use core::starknet::ContractAddress;

#[starknet::interface]
pub trait IAuth<TContractState> {
    fn add_authorized_with_signature(ref self: TContractState, signature: Array<felt252>);
    fn add_authorized(ref self: TContractState, address: ContractAddress);
    fn remove_authorized(ref self: TContractState, address: ContractAddress);
    fn set_verifier(ref self: TContractState, new_verifier: felt252);

    fn add_verifier(ref self: TContractState, new_verifier: ContractAddress);
    fn remove_verifier(ref self: TContractState, verifier: ContractAddress);


    fn lock_actions(ref self: TContractState);
    fn unlock_actions(ref self: TContractState);
    fn set_expiration(ref self: TContractState, expiration_timestamp: u64);

    //getter
    fn can_take_action(self: @TContractState, address: ContractAddress) -> bool;
    fn get_owner(self: @TContractState) -> ContractAddress;
    fn get_expiration(self: @TContractState) -> u64;
}

#[starknet::contract]
mod Auth {
    use core::starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use core::starknet::storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess};
    use core::ecdsa::check_ecdsa_signature;


    use super::IAuth;

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AddressAuthorized: AddressAuthorized,
        AddressRemoved: AddressRemoved,
        VerifierUpdated: VerifierUpdated,
        ExpirationSet: ExpirationSet,
    }

    #[derive(Drop, starknet::Event)]
    struct AddressAuthorized {
        address: ContractAddress,
        authorized_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AddressRemoved {
        address: ContractAddress,
        removed_at: u64
    }

    #[derive(Drop, starknet::Event)]
    struct VerifierUpdated {
        new_verifier: felt252,
        old_verifier: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ExpirationSet {
        timestamp: u64,
        set_at: u64
    }

    #[storage]
    struct Storage {
        authorized_addresses: Map::<ContractAddress, bool>,
        verifier_accounts: Map::<ContractAddress, bool>,
        verifier: felt252,
        owner: ContractAddress,
        actions_locked: bool,
        expiration_timestamp: u64,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, verifier: felt252) {
        self.owner.write(owner);
        self.verifier.write(verifier);

        self.actions_locked.write(false);
        self.expiration_timestamp.write(0);
    }

    #[abi(embed_v0)]
    impl AuthImpl of IAuth<ContractState> {
        fn add_authorized_with_signature(ref self: ContractState, signature: Array<felt252>) {
            let address = get_caller_address();

            assert(self.verify_signature(address, signature), 'Invalid signature');
            self.authorized_addresses.write(address, true);
            self
                .emit(
                    Event::AddressAuthorized(
                        AddressAuthorized { address, authorized_at: get_block_timestamp() }
                    )
                );
        }

        fn add_authorized(ref self: ContractState, address: ContractAddress) {
            let caller = get_caller_address();
            let is_owner = caller == self.owner.read();
            let is_authorizer = self.verifier_accounts.read(caller);
            assert(is_owner || is_authorizer, 'Only owner or verifier can add');

            // Verify the signature is from the authorized verifier
            self.authorized_addresses.write(address, true);
            self
                .emit(
                    Event::AddressAuthorized(
                        AddressAuthorized { address, authorized_at: get_block_timestamp() }
                    )
                );
        }

        fn remove_authorized(ref self: ContractState, address: ContractAddress) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Only owner can remove');

            self.authorized_addresses.write(address, false);
            self
                .emit(
                    Event::AddressRemoved(
                        AddressRemoved { address, removed_at: get_block_timestamp() }
                    )
                );
        }

        fn set_verifier(ref self: ContractState, new_verifier: felt252) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Only owner can change verifier');

            let old_verifier = self.verifier.read();
            self.verifier.write(new_verifier);

            self.emit(Event::VerifierUpdated(VerifierUpdated { new_verifier, old_verifier }));
        }

        fn add_verifier(ref self: ContractState, new_verifier: ContractAddress) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Only owner can add verifier');

            self.verifier_accounts.write(new_verifier, true);
        }

        fn remove_verifier(ref self: ContractState, verifier: ContractAddress) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Only owner can remove verifier');

            self.verifier_accounts.write(verifier, false);
        }

        fn lock_actions(ref self: ContractState) {
            assert(self.owner.read() == get_caller_address(), 'not the owner');
            self.actions_locked.write(true);
        }

        fn unlock_actions(ref self: ContractState) {
            assert(self.owner.read() == get_caller_address(), 'not the owner');
            self.actions_locked.write(false);
        }

        fn set_expiration(ref self: ContractState, expiration_timestamp: u64) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Only owner can set expiration');
            assert(expiration_timestamp > get_block_timestamp(), 'Expiration must be future');
            self.expiration_timestamp.write(expiration_timestamp);
            self
                .emit(
                    Event::ExpirationSet(
                        ExpirationSet {
                            timestamp: expiration_timestamp, set_at: get_block_timestamp()
                        }
                    )
                );
        }


        //getter
        fn get_owner(self: @ContractState) -> ContractAddress {
            return self.owner.read();
        }

        fn get_expiration(self: @ContractState) -> u64 {
            self.expiration_timestamp.read()
        }

        fn can_take_action(self: @ContractState, address: ContractAddress) -> bool {
            let expiration = self.expiration_timestamp.read();
            let is_not_expired = expiration == 0 || get_block_timestamp() < expiration;
            is_not_expired && !self.actions_locked.read() && self.authorized_addresses.read(address)
        }
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn verify_signature(
            self: @ContractState, address: ContractAddress, signature: Array<felt252>
        ) -> bool {
            assert(signature.len() == 2, 'Invalid signature length');

            let verifier = self.verifier.read();
            let signature_r = *signature[0];
            let signature_s = *signature[1];
            let message: felt252 = address.try_into().unwrap();

            return check_ecdsa_signature(message, verifier, signature_r, signature_s);
        }
    }
}
