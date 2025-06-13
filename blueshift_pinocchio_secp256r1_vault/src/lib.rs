#![no_std]

use core::mem::size_of;
use pinocchio::{
    account_info::{AccountInfo, Ref},
    entrypoint,
    instruction::{Seed, Signer},
    nostd_panic_handler,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{
        clock::Clock,
        instructions::{Instructions, IntrospectedInstruction},
        Sysvar,
    },
    ProgramResult,
};
use pinocchio_secp256r1_instruction::{Secp256r1Instruction, Secp256r1Pubkey};
use pinocchio_system::instructions::Transfer;

entrypoint!(process_instruction);
//nostd_panic_handler!();

// 22222222222222222222222222222222222222222222
pub const ID: Pubkey = [
    0x0f, 0x1e, 0x6b, 0x14, 0x21, 0xc0, 0x4a, 0x07, 0x04, 0x31, 0x26, 0x5c, 0x19, 0xc5, 0xbb, 0xee,
    0x19, 0x92, 0xba, 0xe8, 0xaf, 0xd1, 0xcd, 0x07, 0x8e, 0xf8, 0xaf, 0x70, 0x47, 0xdc, 0x11, 0xf7,
];

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data.split_first() {
        Some((Deposit::DISCRIMINATOR, data)) => Deposit::try_from((data, accounts))?.process(),
        Some((Withdraw::DISCRIMINATOR, data)) => Withdraw::try_from((data, accounts))?.process(),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub struct DepositAccounts<'a> {
    pub payer: &'a AccountInfo,
    pub vault: &'a AccountInfo,
}

impl<'a> TryFrom<&'a [AccountInfo]> for DepositAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [payer, vault, _] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Accounts Checks
        if !payer.is_signer() {
            return Err(ProgramError::InvalidAccountOwner);
        }

        if !payer.is_owned_by(&pinocchio_system::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        // if payer.lamports().ne(&0) {
        //     return Err(ProgramError::InvalidAccountData);
        // }

        // Return the accounts
        Ok(Self { payer, vault })
    }
}

pub struct DepositInstructionData {
    pub pubkey: Secp256r1Pubkey,
    pub amount: u64,
}

impl<'a> TryFrom<&'a [u8]> for DepositInstructionData {
    type Error = ProgramError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        if data.len() < 33 + 8 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let (pubkey_bytes, amount_bytes) = data.split_at(33);

        let pubkey = Secp256r1Pubkey::try_from(pubkey_bytes)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let amount = u64::from_le_bytes(
            amount_bytes
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );

        Ok(Self { pubkey, amount })
    }
}

pub struct Deposit<'a> {
    pub accounts: DepositAccounts<'a>,
    pub instruction_data: DepositInstructionData,
}

impl<'a> TryFrom<(&'a [u8], &'a [AccountInfo])> for Deposit<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a [AccountInfo])) -> Result<Self, Self::Error> {
        let accounts = DepositAccounts::try_from(accounts)?;
        let instruction_data = DepositInstructionData::try_from(data)?;

        Ok(Self {
            accounts,
            instruction_data,
        })
    }
}

impl<'a> Deposit<'a> {
    pub const DISCRIMINATOR: &'a u8 = &0;

    pub fn process(&mut self) -> ProgramResult {
        // Check vault address
        let (vault_key, _) = find_program_address(
            &[
                b"vault",
                &self.instruction_data.pubkey[..1],
                &self.instruction_data.pubkey[1..33],
            ],
            &crate::ID,
        );
        if vault_key.ne(self.accounts.vault.key()) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        Transfer {
            from: self.accounts.payer,
            to: self.accounts.vault,
            lamports: self.instruction_data.amount,
        }
        .invoke()?;

        Ok(())
    }
}

pub struct WithdrawAccounts<'a> {
    pub payer: &'a AccountInfo,
    pub vault: &'a AccountInfo,
    pub instructions: &'a AccountInfo,
}

impl<'a> TryFrom<&'a [AccountInfo]> for WithdrawAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [payer, vault, instructions, _system_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        if !vault.is_owned_by(&pinocchio_system::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        if vault.lamports().eq(&0) {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(Self {
            payer,
            vault,
            instructions,
        })
    }
}

pub struct WithdrawInstructionData {
    pub bump: [u8; 1],
}

impl<'a> TryFrom<&'a [u8]> for WithdrawInstructionData {
    type Error = ProgramError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(unsafe {
            core::mem::transmute(
                TryInto::<[u8; size_of::<WithdrawInstructionData>()]>::try_into(data)
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            )
        })
    }
}

pub struct Withdraw<'a> {
    pub accounts: WithdrawAccounts<'a>,
    pub instruction_data: WithdrawInstructionData,
}

impl<'a> TryFrom<(&'a [u8], &'a [AccountInfo])> for Withdraw<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a [AccountInfo])) -> Result<Self, Self::Error> {
        let accounts = WithdrawAccounts::try_from(accounts)?;
        let instruction_data = WithdrawInstructionData::try_from(data)?;

        Ok(Self {
            accounts,
            instruction_data,
        })
    }
}

impl<'a> Withdraw<'a> {
    pub const DISCRIMINATOR: &'a u8 = &1;

    pub fn process(&mut self) -> ProgramResult {
        // Deserialize our instructions
        let instructions: Instructions<Ref<[u8]>> =
            Instructions::try_from(self.accounts.instructions)?;
        // Get instruction directly after this one
        let ix: IntrospectedInstruction = instructions.get_instruction_relative(1)?;
        // Get Secp256r1 instruction
        let secp256r1_ix = Secp256r1Instruction::try_from(&ix)?;
        // Enforce that we only have one signature
        if secp256r1_ix.num_signatures() != 1 {
            return Err(ProgramError::InvalidInstructionData);
        }
        // Enforce that the signer of the first signature is our PDA owner
        let signer: Secp256r1Pubkey = *secp256r1_ix.get_signer(0)?;

        // Check that our fee payer is the correct

        let message_data = secp256r1_ix.get_message_data(0)?;
        if message_data.len() < 32 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (payer, expiry) = message_data.split_at(32);
        if self.accounts.payer.key().ne(payer) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        // Get current timestamp
        let now = Clock::get()?.unix_timestamp;
        // Get signature expiry timestamp
        let expiry = i64::from_le_bytes(
            expiry
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );
        if now > expiry {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Create signer seeds for our CPI
        let seeds = [
            Seed::from(b"vault"),
            Seed::from(signer[..1].as_ref()),
            Seed::from(signer[1..].as_ref()),
            Seed::from(&self.instruction_data.bump),
        ];
        let signers = [Signer::from(&seeds)];

        Transfer {
            from: self.accounts.vault,
            to: self.accounts.payer,
            lamports: self.accounts.vault.lamports(),
        }
        .invoke_signed(&signers)
    }
}
