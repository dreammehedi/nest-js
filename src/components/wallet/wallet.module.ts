import { Module } from '@nestjs/common';
import { WalletController } from './wallet.controller';
import { WalletService } from './wallet.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Wallet, WalletSchema } from 'src/schema/Wallet/wallet.schema';
import { User, UserSchema } from 'src/schema/User/user.schema';
import { Network, NetworkSchema } from 'src/schema/Network/network.schema';
import { Coin, CoinSchema } from 'src/schema/Coin/coin.schema';
import { Balance, BalanceSchema } from 'src/schema/Balance/balance.schema';
import {
  Transaction,
  TransactionSchema,
} from 'src/schema/Transaction/transaction.schema';
import { UtilsService } from '../utils/utils.service';
import {
  CoinPrice,
  CoinPriceSchema,
} from 'src/schema/CoinPrice/coin-price.schema';
import { FeeInfo, FeeInfoSchema } from 'src/schema/FeeInfo/fee-info.schema';
import { Currency, CurrencySchema } from 'src/schema/Currency/currency.schema';
import { NftService } from '../nft/nft.service';
import { NFT, NFTSchema } from 'src/schema/Nft/nft.schema';
import { CoinsModule } from '../coins/coins.module';
import { CoinsService } from '../coins/coins.service';
import { UserStakeInfo, UserStakeInfoSchema } from 'src/schema/UserStakeInfo/user-stake-info.schema';
import { StakingInfo, StakingInfoSchema } from 'src/schema/StakingInfo/staking-info.schema';
import { StakingPlan, StakingPlanSchema } from 'src/schema/StakingPlan/staking-plan.schema';
import { StakeInvestmentInfo, StakeInvestmentInfoSchema } from 'src/schema/StakeInvestmentInfo/stake-investment-info.schema';
import { FiatBalance, FiatBalanceSchema } from 'src/schema/FiatBalance/fiat-balance.schema';
import { DonationOrganization, DonationOrganizationSchema } from 'src/schema/DonationOrganization/donation-organization.schema';
import { DepositBankDetail, DepositBankDetailSchema } from 'src/schema/DepositBankDetail/deposit-bank-detail.schema';

@Module({
  imports: [
    CoinsModule,
    MongooseModule.forFeature([
      { name: Wallet.name, schema: WalletSchema },
      { name: User.name, schema: UserSchema },
      { name: Network.name, schema: NetworkSchema },
      { name: Coin.name, schema: CoinSchema },
      { name: Balance.name, schema: BalanceSchema },
      { name: Transaction.name, schema: TransactionSchema },
      { name: CoinPrice.name, schema: CoinPriceSchema },
      { name: FeeInfo.name, schema: FeeInfoSchema },
      { name: Currency.name, schema: CurrencySchema },
      { name: NFT.name, schema: NFTSchema },
      { name: StakingPlan.name, schema: StakingPlanSchema },
      { name: StakingInfo.name, schema: StakingInfoSchema },
      { name: UserStakeInfo.name, schema: UserStakeInfoSchema },
      { name: StakeInvestmentInfo.name, schema: StakeInvestmentInfoSchema },
      { name: FiatBalance.name, schema: FiatBalanceSchema },
      { name: DonationOrganization.name, schema: DonationOrganizationSchema },
      { name: DepositBankDetail.name, schema: DepositBankDetailSchema },
    ]),
  ],
  controllers: [WalletController],
  providers: [WalletService, UtilsService, NftService, CoinsService],
  exports: [WalletService],
})
export class WalletModule { }
