"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WalletModule = void 0;
const common_1 = require("@nestjs/common");
const wallet_controller_1 = require("./wallet.controller");
const wallet_service_1 = require("./wallet.service");
const mongoose_1 = require("@nestjs/mongoose");
const wallet_schema_1 = require("../../schema/Wallet/wallet.schema");
const user_schema_1 = require("../../schema/User/user.schema");
const network_schema_1 = require("../../schema/Network/network.schema");
const coin_schema_1 = require("../../schema/Coin/coin.schema");
const balance_schema_1 = require("../../schema/Balance/balance.schema");
const transaction_schema_1 = require("../../schema/Transaction/transaction.schema");
const utils_service_1 = require("../utils/utils.service");
const coin_price_schema_1 = require("../../schema/CoinPrice/coin-price.schema");
const fee_info_schema_1 = require("../../schema/FeeInfo/fee-info.schema");
const currency_schema_1 = require("../../schema/Currency/currency.schema");
const nft_service_1 = require("../nft/nft.service");
const nft_schema_1 = require("../../schema/Nft/nft.schema");
const coins_module_1 = require("../coins/coins.module");
const coins_service_1 = require("../coins/coins.service");
const user_stake_info_schema_1 = require("../../schema/UserStakeInfo/user-stake-info.schema");
const staking_info_schema_1 = require("../../schema/StakingInfo/staking-info.schema");
const staking_plan_schema_1 = require("../../schema/StakingPlan/staking-plan.schema");
const stake_investment_info_schema_1 = require("../../schema/StakeInvestmentInfo/stake-investment-info.schema");
const fiat_balance_schema_1 = require("../../schema/FiatBalance/fiat-balance.schema");
const donation_organization_schema_1 = require("../../schema/DonationOrganization/donation-organization.schema");
const deposit_bank_detail_schema_1 = require("../../schema/DepositBankDetail/deposit-bank-detail.schema");
let WalletModule = class WalletModule {
};
exports.WalletModule = WalletModule;
exports.WalletModule = WalletModule = __decorate([
    (0, common_1.Module)({
        imports: [
            coins_module_1.CoinsModule,
            mongoose_1.MongooseModule.forFeature([
                { name: wallet_schema_1.Wallet.name, schema: wallet_schema_1.WalletSchema },
                { name: user_schema_1.User.name, schema: user_schema_1.UserSchema },
                { name: network_schema_1.Network.name, schema: network_schema_1.NetworkSchema },
                { name: coin_schema_1.Coin.name, schema: coin_schema_1.CoinSchema },
                { name: balance_schema_1.Balance.name, schema: balance_schema_1.BalanceSchema },
                { name: transaction_schema_1.Transaction.name, schema: transaction_schema_1.TransactionSchema },
                { name: coin_price_schema_1.CoinPrice.name, schema: coin_price_schema_1.CoinPriceSchema },
                { name: fee_info_schema_1.FeeInfo.name, schema: fee_info_schema_1.FeeInfoSchema },
                { name: currency_schema_1.Currency.name, schema: currency_schema_1.CurrencySchema },
                { name: nft_schema_1.NFT.name, schema: nft_schema_1.NFTSchema },
                { name: staking_plan_schema_1.StakingPlan.name, schema: staking_plan_schema_1.StakingPlanSchema },
                { name: staking_info_schema_1.StakingInfo.name, schema: staking_info_schema_1.StakingInfoSchema },
                { name: user_stake_info_schema_1.UserStakeInfo.name, schema: user_stake_info_schema_1.UserStakeInfoSchema },
                { name: stake_investment_info_schema_1.StakeInvestmentInfo.name, schema: stake_investment_info_schema_1.StakeInvestmentInfoSchema },
                { name: fiat_balance_schema_1.FiatBalance.name, schema: fiat_balance_schema_1.FiatBalanceSchema },
                { name: donation_organization_schema_1.DonationOrganization.name, schema: donation_organization_schema_1.DonationOrganizationSchema },
                { name: deposit_bank_detail_schema_1.DepositBankDetail.name, schema: deposit_bank_detail_schema_1.DepositBankDetailSchema },
            ]),
        ],
        controllers: [wallet_controller_1.WalletController],
        providers: [wallet_service_1.WalletService, utils_service_1.UtilsService, nft_service_1.NftService, coins_service_1.CoinsService],
        exports: [wallet_service_1.WalletService],
    })
], WalletModule);
//# sourceMappingURL=wallet.module.js.map