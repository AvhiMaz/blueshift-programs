use anchor_lang::prelude::*;

declare_id!("3qSEKwxFrZYLNhqufv9647bfZnJpxLHbQU7rL6pspMXw");

#[program]
pub mod blueshift_anchor_escrow {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
