import { Module } from '@nestjs/common';
import { CoinsController } from './coins.controller';
import { CoinsService } from './coins.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Coin, CoinSchema } from 'src/schema/Coin/coin.schema';
import { Network, NetworkSchema } from 'src/schema/Network/network.schema';
import { Currency, CurrencySchema } from 'src/schema/Currency/currency.schema';
import {
  CoinPrice,
  CoinPriceSchema,
} from 'src/schema/CoinPrice/coin-price.schema';
import { FeeInfo, FeeInfoSchema } from 'src/schema/FeeInfo/fee-info.schema';
import { StakingPlan, StakingPlanSchema } from 'src/schema/StakingPlan/staking-plan.schema';
import { StakingInfo, StakingInfoSchema } from 'src/schema/StakingInfo/staking-info.schema';
import { UserStakeInfo, UserStakeInfoSchema } from 'src/schema/UserStakeInfo/user-stake-info.schema';
import { User, UserSchema } from 'src/schema/User/user.schema';
import { StakeInvestmentInfo, StakeInvestmentInfoSchema } from 'src/schema/StakeInvestmentInfo/stake-investment-info.schema';
import { Wallet, WalletSchema } from 'src/schema/Wallet/wallet.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Coin.name, schema: CoinSchema },
      { name: Network.name, schema: NetworkSchema },
      { name: Currency.name, schema: CurrencySchema },
      { name: CoinPrice.name, schema: CoinPriceSchema },
      { name: FeeInfo.name, schema: FeeInfoSchema },
      { name: StakingPlan.name, schema: StakingPlanSchema },
      { name: StakingInfo.name, schema: StakingInfoSchema },
      { name: UserStakeInfo.name, schema: UserStakeInfoSchema },
      { name: StakeInvestmentInfo.name, schema: StakeInvestmentInfoSchema },
      { name: User.name, schema: UserSchema },
      { name: Wallet.name, schema: WalletSchema },
    ]),
  ],
  controllers: [CoinsController],
  providers: [CoinsService],
})
export class CoinsModule { }
