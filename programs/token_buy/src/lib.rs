use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{mint_to, Mint, MintTo, Token, TokenAccount},
};
use pyth_solana_receiver_sdk::price_update::PriceUpdateV2;
// use anchor_spl::token::accessor::authority;
declare_id!("6z1xKktrGLpRGX4MfxeFLEYtze3f2mYBQdgdAj8CjqHW");

#[program]
pub mod token_sale {
    use super::*;

     pub fn initialize_sale(ctx: Context<InitializeSale>, token_price_usd: f64) -> Result<()> {
        let sale_config = &mut ctx.accounts.sale_config;
        sale_config.authority = ctx.accounts.authority.key();
        sale_config.token_price_usd = token_price_usd;
        sale_config.paused = false;

        Ok(())
    }

    pub fn buy_tokens(ctx: Context<BuyTokens>, sol_amount: u64) -> Result<()> {
        // Check if sale is paused
        let sale_config = &ctx.accounts.sale_config;
        require!(!sale_config.paused, ErrorCode::SalePaused);

        // Get SOL/USD price from Pyth
        let maximum_age: u64 = 30; // 30 seconds maximum age for price data
        // SOL/USD price feed ID on Pyth
        let feed_id: [u8; 32] = get_feed_id_from_hex(
            "Ca7cXpqoq0GqEHxTnXzf7D6r5SDiGd1Ja6oFgwX9oRE6"
        )?;
        
        let price_data = ctx.accounts.price_update.get_price_no_older_than(
            &Clock::get()?,
            maximum_age,
            &feed_id
        )?;

        // Calculate SOL price in USD (handling the exponent)
        let sol_price_usd = (price_data.price as f64) * 10f64.powi(price_data.exponent);

        // Calculate token amount based on SOL amount and token price
        let token_price_usd = sale_config.token_price_usd;
        let sol_amount_usd = sol_amount as f64 / 10_f64.powf(9.0) * sol_price_usd;
        let token_amount = (sol_amount_usd / token_price_usd
            * 10_f64.powf(ctx.accounts.mint.decimals as f64)) as u64;

        // Transfer SOL to sale authority
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.buyer.to_account_info(),
                to: ctx.accounts.sale_authority.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, sol_amount)?;

        // Mint tokens to buyer's associated token account
        let mint_context = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.buyer_token_account.to_account_info(),
                authority: ctx.accounts.mint_authority.to_account_info(),
            },
            &[],
        );
        mint_to(mint_context, token_amount)?;

        Ok(())
    }

    pub fn withdraw_sol(ctx: Context<WithdrawSol>, amount: u64) -> Result<()> {
        let sale_config = &ctx.accounts.sale_config;
        require!(
            sale_config.authority == ctx.accounts.authority.key(),
            ErrorCode::Unauthorized
        );

        let current_balance = ctx.accounts.sale_authority.lamports();
        require!(current_balance >= amount, ErrorCode::InsufficientFunds);

        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.sale_authority.to_account_info(),
                to: ctx.accounts.recipient.to_account_info(),
            },
        );

        anchor_lang::system_program::transfer(cpi_context, amount)?;

        Ok(())
    }

    pub fn pause_sale(ctx: Context<AdminControl>) -> Result<()> {
        let sale_config = &mut ctx.accounts.sale_config;
        sale_config.paused = true;
        Ok(())
    }

    pub fn resume_sale(ctx: Context<AdminControl>) -> Result<()> {
        let sale_config = &mut ctx.accounts.sale_config;
        sale_config.paused = false;
        Ok(())
    }
}

fn get_feed_id_from_hex(hex_string: &str) -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    let decoded = bs58::decode(hex_string)
        .into_vec()
        .map_err(|_| error!(ErrorCode::InvalidPythFeedId))?;
    
    if decoded.len() != 32 {
        return Err(error!(ErrorCode::InvalidPythFeedId));
    }
    
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

#[derive(Accounts)]
pub struct BuyTokens<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,

    #[account(mut)]
    pub sale_authority: SystemAccount<'info>,

     #[account(constraint = sale_config.authority == authority.key() @ ErrorCode::Unauthorized)]
    pub sale_config: Account<'info, SaleConfig>,

    pub authority: Signer<'info>,

    #[account(mut)]
    pub mint: Account<'info, Mint>,

    #[account(
        init_if_needed,
        payer = buyer,
        associated_token::mint = mint,
        associated_token::authority = buyer,
    )]
    pub buyer_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub price_update: Account<'info, PriceUpdateV2>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,

    #[account(seeds = ["mint".as_bytes()], bump)]
    pub mint_authority: AccountInfo<'info>,
}
#[derive(Accounts)]
pub struct WithdrawSol<'info> {
     #[account(
        mut,
        constraint = sale_config.authority == authority.key() @ ErrorCode::Unauthorized
    )]
    pub sale_config: Account<'info, SaleConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(mut)]
    pub sale_authority: SystemAccount<'info>,

    /// CHECK: Recipient account where SOL will be withdrawn
    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeSale<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init, 
        payer = authority, 
        space = 8 + 32 + 8 + 1
    )]
    pub sale_config: Account<'info, SaleConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminControl<'info> {
    #[account(mut, has_one = authority)]
    pub sale_config: Account<'info, SaleConfig>,
    pub authority: Signer<'info>,
}

#[account]
pub struct SaleConfig {
    pub authority: Pubkey,
    pub token_price_usd: f64,
    pub paused: bool,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Token sale is currently paused")]
    SalePaused,

    #[msg("Unauthorized to perform this action")]
    Unauthorized,

    #[msg("Insufficient funds for withdrawal")]
    InsufficientFunds,

    #[msg("Invalid Pyth feed ID")]
    InvalidPythFeedId,
}