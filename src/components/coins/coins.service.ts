import { BadRequestException, Injectable, Scope } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Coin, CoinDocument } from 'src/schema/Coin/coin.schema';
import { Network, NetworkDocument } from 'src/schema/Network/network.schema';
import {
  Currency,
  CurrencyDocument,
} from 'src/schema/Currency/currency.schema';
import {
  CoinPrice,
  CoinPriceDocument,
} from 'src/schema/CoinPrice/coin-price.schema';
import { Cron } from '@nestjs/schedule';
import { FeeInfo, FeeInfoDocument } from 'src/schema/FeeInfo/fee-info.schema';
import { dbCoins } from 'src/utils/utils';
import { StakeService } from '../stake/stake.service';
import { StakingPlan, StakingPlanDocument } from 'src/schema/StakingPlan/staking-plan.schema';
import { StakingInfo, StakingInfoDocument } from 'src/schema/StakingInfo/staking-info.schema';
import { User, UserDocument } from 'src/schema/User/user.schema';
import { UserStakeInfo, UserStakeInfoDocument } from 'src/schema/UserStakeInfo/user-stake-info.schema';
import { StakeInvestmentInfo, StakeInvestmentInfoDocument } from 'src/schema/StakeInvestmentInfo/stake-investment-info.schema';
import { Wallet, WalletDocument } from 'src/schema/Wallet/wallet.schema';
import { of } from 'rxjs';

const Web3 = require('web3');

@Injectable({ scope: Scope.DEFAULT })
export class CoinsService {
  constructor(
    @InjectModel(Coin.name) private _coinModel: Model<CoinDocument>,
    @InjectModel(Network.name) private _networkModel: Model<NetworkDocument>,
    @InjectModel(Currency.name) private _currencyModel: Model<CurrencyDocument>,
    @InjectModel(CoinPrice.name)
    private _coinPriceModel: Model<CoinPriceDocument>,
    @InjectModel(FeeInfo.name) private _feeInfoModel: Model<FeeInfoDocument>,
    @InjectModel(StakingPlan.name) private _stakingPlanModel: Model<StakingPlanDocument>,
    @InjectModel(StakingInfo.name) private _stakingInfoModel: Model<StakingInfoDocument>,
    @InjectModel(UserStakeInfo.name) private _userStakeInfoModel: Model<UserStakeInfoDocument>,
    @InjectModel(StakeInvestmentInfo.name) private _stakeInvestmentInfoModel: Model<StakeInvestmentInfoDocument>,
    @InjectModel(User.name) private _userModel: Model<UserDocument>,
    @InjectModel(Wallet.name) private _walletModel: Model<WalletDocument>,
  ) {
    // try {
    //   this.addCurrencies();
    this.initDbCoins();
    //   this.updateStakingInfoForAllCoins();
    //   this.getInvestmentDataForAllUsers();

    //   this.getAllInvestmentData()

    //   this.updatePriceForAllCurrencies();
    // } catch (err) {
    //   console.error(err);
    // }
  }

  async initDbCoins() {
    try {
      const withdrawFeeDocument = await this._feeInfoModel.findOne({
        feeName: 'withdraw_fiat_fee',
      });
      if (!withdrawFeeDocument) {
        await new this._feeInfoModel({
          feeName: 'withdraw_fiat_fee',
          feePercentage: 2,
        }).save();
      }

      const swapFeeDocument = await this._feeInfoModel.findOne({
        feeName: 'swap_fee',
      });
      if (!swapFeeDocument) {
        await new this._feeInfoModel({
          feeName: 'swap_fee',
          feePercentage: 2,
        }).save();
      }

      if (process.env.IS_INSERT_COINS == 'true') {
        console.log(process.env.IS_INSERT_COINS);

        for (const dbCoin of dbCoins) {
          let networkDocument = await this._networkModel.findOne({
            name: dbCoin.networkId.name,
          });
          if (!networkDocument) {
            networkDocument = await new this._networkModel({
              name: dbCoin.networkId.name,
              chainId: dbCoin.networkId.chainId,
              symbol: dbCoin.networkId.symbol,
              logoUrl: dbCoin.networkId.logoUrl,
              rpcUrl: dbCoin.networkId.rpcUrl,
              isMainnet: dbCoin.networkId.isMainnet,
              networkName: dbCoin.networkId.networkName,
              networkType: dbCoin.networkId.networkType,
              isDeleted: false,
              isActive: true,
            }).save();
          } else {
            await networkDocument?.updateOne({
              $set: {
                logoUrl: dbCoin?.networkId?.logoUrl,
                scanUrl: dbCoin?.networkId?.scanUrl,
              }
            })
          }

          const coinDocument = await this._coinModel.findOne({
            name: dbCoin.name,
          });

          if (!coinDocument) {
            debugger
            await new this._coinModel({
              name: dbCoin.name,
              symbol: dbCoin.symbol,
              icon: dbCoin.icon,
              coinNameId: dbCoin.coinNameId,
              isToken: dbCoin.isToken,
              contractAddress: dbCoin.contractAddress,
              isStakingAvailable: dbCoin?.isStakingAvailable || false,
              stakingContractAddress: dbCoin?.stakingContractAddress || "",
              decimal: dbCoin.decimal,
              price: 0,
              priceFormer: 0,
              priceMarket: 0,
              priceFrom: dbCoin?.priceFrom,
              swapFee: dbCoin.swapFee,
              networkId: networkDocument.id,
              isActive: true,
              priceChange: 0,
              sort: dbCoin.sort,
              unit: dbCoin.unit,
              onRampId: dbCoin?.onRampId,
              isDeleted: false,
              onRampNetworkId: dbCoin?.onRampNetworkId,
            }).save();
          }
          else {
            await coinDocument?.updateOne({
              $set: {
                icon: dbCoin?.icon,
                priceFrom: dbCoin?.priceFrom,
                coinNameId: dbCoin?.coinNameId,
              }
            })
          }

          {
            if (dbCoin?.isStakingAvailable) {
              const stakingService = new StakeService(dbCoin?.stakingContractAddress, networkDocument?.rpcUrl, dbCoin?.contractAddress);

              const stakingPlans = await stakingService.getStakingPlans();
              debugger
              await Promise.all(stakingPlans.map(async (stakingPlan) => {
                await this._stakingPlanModel.updateOne({
                  planId: stakingPlan.id,
                  coinId: coinDocument?.id,
                  networkId: networkDocument?.id,
                }, {
                  planId: stakingPlan.id,
                  coinId: coinDocument?.id,
                  networkId: networkDocument?.id,
                  stakingContractAddress: dbCoin?.stakingContractAddress || "",
                  duration: stakingPlan.duration,
                  interestRate: stakingPlan.interestRate,
                  isActive: stakingPlan.isActive,
                }, { upsert: true });
              }));
            }
          }
        }
      }
    } catch (err) {
      console.log(err);
    }
  }

  async getCurrencies(limit: number, offset: number, currencyName: string) {
    limit = limit ? Number(limit) : 10;
    offset = offset ? Number(offset) : 0;

    let query = {};
    if (currencyName) {
      const regex = new RegExp(currencyName, 'i');
      query = {
        ...query,
        name: { $regex: regex },
      };
    }

    const currencies = await this._currencyModel
      .find(query)
      .sort({ name: 1 })
      .skip(offset)
      .limit(limit);

    return currencies;
  }

  async getCoins(
    limit: number,
    offset: number,
    coinId: string,
    networkId: string,
    amount = 1,
  ) {
    try {
      limit = limit ? Number(limit) : 10;
      offset = offset ? Number(offset) : 0;
      amount = amount ? Number(amount) : 1;

      let query = {};

      if (coinId) {
        query = {
          ...query,
          _id: coinId,
        };
      }

      if (networkId) {
        query = {
          ...query,
          networkId: networkId,
        };
      }

      const coinsData = await this._coinModel.aggregate([
        {
          $match: {
            isDeleted: false,
            isActive: true,
            ...query,
          },
        },
        {
          $lookup: {
            from: 'networks',
            localField: 'networkId',
            foreignField: '_id',
            as: 'network',
          },
        },
        {
          $unwind: '$network',
        },
        {
          $lookup: {
            from: 'stakingplans',
            localField: '_id',
            foreignField: 'coinId',
            as: "stakingPlans"
          },
        },
        {
          $skip: offset,
        },
        {
          $limit: limit,
        },
        {
          $addFields: {
            id: '$_id',
            'network.id': '$network._id',
          },
        },
        {
          $project: {
            _id: 0,
            'network._id': 0,
          },
        },
      ]);

      const coins = coinsData?.map((coinItem) => {
        const coinReturn = JSON.parse(JSON.stringify(coinItem));
        let amountAfterFee = amount;
        if (coinItem.swapFee) {
          amountAfterFee = amountAfterFee - coinItem.swapFee;
        }
        coinReturn.swapAmount = coinItem.price * amountAfterFee;
        return coinReturn;
      });

      return coins
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err.message);
    }
  }

  async getCoinsPrice(
    limit: number,
    offset: number,
    coinNameSearch: string,
    networkId: string,
    currencyId: string,
  ) {
    try {
      limit = limit ? Number(limit) : 10;
      offset = offset ? Number(offset) : 0;
      let query = {};

      if (coinNameSearch) {
        query = {
          ...query,
          name: { $regex: coinNameSearch, $options: 'i' },
        };
      }

      if (networkId) {
        query = {
          ...query,
          networkId: networkId,
        };
      }

      if (currencyId) {
        query = {
          ...query,
          currencyId: currencyId,
        };
      }

      const coins = await this._coinPriceModel
        .aggregate([
          {
            $match: {
              ...query,
            },
          },
          {
            $lookup: {
              from: 'coins',
              localField: 'coinId',
              foreignField: '_id',
              as: 'coin',
            },
          },
          {
            $unwind: '$coin',
          },
          {
            $lookup: {
              from: 'currencies',
              localField: 'currencyId',
              foreignField: '_id',
              as: 'currency',
            },
          },
          {
            $unwind: '$currency',
          },
          {
            $skip: offset,
          },
          {
            $limit: limit,
          },
          {
            $addFields: {
              displayName: '$coin.symbol' + '/' + '$currency.symbol',
              id: '$_id',
              coinId: '$coin._id',
              coinNameId: '$coin.coinNameId',
              currencyName: '$currency.name',
              currencySymbol: '$currency.symbol',
              name: '$coin.name',
              symbol: '$coin.symbol',
              icon: '$coin.icon',
              price: '$price',
              priceMarket: '$priceMarket',
              priceChange: '$priceChange',
            },
          },
          {
            $project: {
              displayName: 1,
              id: 1,
              coinId: 1,
              coinNameId: 1,
              currencyName: 1,
              currencySymbol: 1,
              name: 1,
              symbol: 1,
              icon: 1,
              price: 1,
              priceMarket: 1,
              priceChange: 1,
            },
          },
        ])
        .then((coins) => {
          return coins.map((coin) => {
            return {
              ...coin,
              displayName: `${coin?.symbol}/${coin?.currencySymbol}`,
            };
          });
        });

      return coins;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err.message);
    }
  }

  // async updatePrice(updatePriceDTO: UpdatePriceDTO) {
  //   try {
  //     const coinDocument = await this._coinModel.findOne({ _id: updatePriceDTO.coinId });
  //     await this._coinModel.updateOne({ _id: updatePriceDTO.coinId }, {
  //       price: updatePriceDTO.price,
  //       priceFormer: coinDocument?.price,
  //     })
  //     return {
  //       message: "success"
  //     };
  //   } catch (err) {
  //     console.log(err?.message);
  //     throw new BadRequestException(err?.message);
  //   }
  // }

  async updatePriceFromCoin() {
    try {
      // const baseUrl =
    } catch (err) {
      console.log(err?.message);
      throw new BadRequestException(err?.message);
    }
  }

  async getNetworks() {
    try {
      const networkData = await this._networkModel
        .find({ isDeleted: false })
        .sort({ name: -1 });

      return networkData;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err.message);
    }
  }

  async updatePriceFromCoinGeckoTerminal(coin: CoinDocument) {
    try {
      const networkData = await this._networkModel.findOne({ _id: coin?.networkId });
      if (!networkData) {
        throw new Error('Network not found');
      }

      const url = `${process.env.COINGECKO_TERMINAL_API_URL}simple/networks/${networkData?.symbol?.toLowerCase()}/token_price/${coin?.coinNameId}`;

      const response = await fetch(url);

      const data = await response.json();

      const usdPrice = Number(data?.data?.attributes?.token_prices?.[coin?.coinNameId]);

      const usdtCoin = await this._coinModel.findOne({ coinNameId: 'tether' });

      const usdPricesInAllCurrencies = await this._coinPriceModel.find({ coinId: usdtCoin?.id });

      const currencies = await this._currencyModel.find({ isDeleted: false, isActive: true });

      const coinPriceInAllCurrencies =
        currencies.map((currency) => {
          const usdPriceInCurrency = usdPricesInAllCurrencies.find((usdPriceInCurrency) => usdPriceInCurrency?.currencyId == currency
            ?.id)?.price;

          const price = usdPrice * usdPriceInCurrency;

          return {
            price: price,
            currencyId: currency?.id,
            currencyName: currency?.name,
          };
        });

      return await Promise.all(
        coinPriceInAllCurrencies.map(async (coinPrice) => {
          console.log(
            'updating price for',
            coin?.name,
            coinPrice?.currencyName,
            coinPrice?.price,
          );

          return await this._coinPriceModel.updateOne(
            {
              coinId: coin?.id,
              currencyId: coinPrice?.currencyId,
            },
            {
              price: coinPrice?.price,
              priceChange: 0,
              priceMarket: 0,
              networkId: coin?.networkId,
              name: coin?.name,
            },
            { upsert: true },
          );
        }),
      );
    }
    catch (err) {
      console.log(err);
    }
  }

  async updatePrice(coin: CoinDocument, currencies: CurrencyDocument[]) {
    try {
      if (!coin) {
        throw new Error('Coin not found');
      }

      if (coin?.priceFrom === 'COINGECKO') {
        // const url = `${process.env.COINGECKO_API_URL}simple/price?ids=${coin?.coinNameId}&vs_currencies=${currency?.coinGeckoId}&include_24hr_change=true&include_market_cap=true`;
        const url = `${process.env.COINGECKO_API_URL}coins/${coin?.coinNameId}`;

        const response = await fetch(url);

        const data = await response.json();

        return await Promise.all(
          currencies.map(async (currency) => {
            const price =
              data?.market_data?.current_price?.[currency?.coinGeckoId];
            const priceChange =
              data?.market_data?.[`price_change_percentage_24h_in_currency`]?.[
              currency?.coinGeckoId
              ];
            const priceMarket =
              data?.market_data?.[`market_cap`]?.[currency?.coinGeckoId];
            console.log(
              'updating price for',
              coin?.name,
              currency?.name,
              price,
              priceChange,
              priceMarket,
            );

            if (!price) {
              return;
            }

            return await this._coinPriceModel.updateOne(
              {
                coinId: coin?.id,
                currencyId: currency?.id,
              },
              {
                price: price,
                priceChange: priceChange,
                priceMarket: priceMarket,
                networkId: coin?.networkId,
                name: coin?.name,
              },
              { upsert: true },
            );
          }),
        );
      } else if (coin?.priceFrom === "COINGECKO_TERMINAL") {
        const networkData = await this._networkModel.findOne({ _id: coin?.networkId });
        if (!networkData) {
          throw new Error('Network not found');
        }

        const url = `${process.env.COINGECKO_TERMINAL_API_URL}simple/networks/${networkData?.symbol?.toLowerCase()}/token_price/${coin?.coinNameId}`;

        const response = await fetch(url);

        const data = await response.json();

        const usdPrice = Number(data?.data?.attributes?.token_prices?.[coin?.coinNameId]);

        const usdtCoin = await this._coinModel.findOne({ coinNameId: 'tether' });

        const usdPricesInAllCurrencies = await this._coinPriceModel.find({ coinId: usdtCoin?.id });

        const coinPriceInAllCurrencies =
          currencies.map((currency) => {
            const usdPriceInCurrency = usdPricesInAllCurrencies.find((usdPriceInCurrency) => usdPriceInCurrency?.currencyId == currency
              ?.id)?.price;

            const price = usdPrice * usdPriceInCurrency;

            return {
              price: price,
              currencyId: currency?.id,
              currencyName: currency?.name,
            };
          });

        return await Promise.all(
          coinPriceInAllCurrencies.map(async (coinPrice) => {
            console.log(
              'updating price for',
              coin?.name,
              coinPrice?.currencyName,
              coinPrice?.price,
            );

            return await this._coinPriceModel.updateOne(
              {
                coinId: coin?.id,
                currencyId: coinPrice?.currencyId,
              },
              {
                price: coinPrice?.price,
                priceChange: 0,
                priceMarket: 0,
                networkId: coin?.networkId,
                name: coin?.name,
              },
              { upsert: true },
            );
          }),
        );

      }
    } catch (err) {
      console.log(err);
    }
  }

  //Every 5 minutes
  @Cron('0 */5 * * * *')
  async updatePriceForAllCurrencies() {
    try {
      const allCurrencies = await this._currencyModel.find({
        isDeleted: false,
        isActive: true,
      });
      const allCoins = await this._coinModel.find({
        isDeleted: false,
        isActive: true,
      });

      await Promise.all(
        allCoins?.filter(item => item?.priceFrom === "COINGECKO").map(async (coin) => {
          await this.updatePrice(coin, allCurrencies);
        }),
      );

      // update price for coins from coingecko terminal
      // await Promise.all(
      //   allCoins?.filter(item => item?.priceFrom === "COINGECKO_TERMINAL").map(async (coin) => {
      //     await this.updatePriceFromCoinGeckoTerminal(coin);
      //   }),
      // );

      for await (const coin of allCoins?.filter(item => item?.priceFrom === "COINGECKO_TERMINAL")) {
        if (coin?.priceFrom === "COINGECKO_TERMINAL") {
          await this.updatePriceFromCoinGeckoTerminal(coin);
        }
      }
    } catch (err) {
      console.log(err);
    }
  }

  @Cron('0 */30 * * * *')
  async updateStakingInfoForAllCoins(
    coinIds: string[] = [],
  ) {
    try {
      const query = {};
      if (coinIds.length) {
        query['coinId'] = { $in: coinIds };
      }
      const allCoins = await this._coinModel.aggregate([
        {
          $match: {
            isDeleted: false,
            isActive: true,
            isStakingAvailable: true,
            ...query,
          },
        },
        {
          $lookup: {
            from: 'networks',
            localField: 'networkId',
            foreignField: '_id',
            as: 'network',
          },
        },
        {
          $unwind: '$network',
        },
        {
          $addFields: {
            id: '$_id',
            'network.id': '$network._id',
          },
        },
        {
          $project: {
            _id: 0,
            'network._id': 0,
          },
        },
      ]);

      await Promise.all(
        allCoins.map(async (coin) => {
          const stakingService = new StakeService(coin?.stakingContractAddress, coin?.network?.rpcUrl, coin?.contractAddress);

          const stakingInfo = await stakingService.getStakingInformation();

          await this._stakingInfoModel.updateOne({
            coinId: coin?.id,
            networkId: coin?.network?.id,
          }, {
            totalInvestments: stakingInfo?.totalInvestments,
            totalStaked: stakingInfo?.totalStaked,
            totalReward: stakingInfo?.totalRewards,
            stakingContractAddress: coin?.stakingContractAddress,
            coinId: coin?.id,
            networkId: coin?.network?.id,
          }, { upsert: true });
        }));
      console.log('Staking info updated');

      await this.getInvestmentDataForAllUsers();

    } catch (err) {
      console.log(err);
    }
  }

  async getCoinPrice(coinId: string, currencyId: string) {
    try {
      const coinPrice = await this._coinPriceModel.aggregate([
        {
          $match: {
            coinId: coinId,
            currencyId: currencyId,
          },
        },
        {
          $lookup: {
            from: 'coins',
            localField: 'coinId',
            foreignField: '_id',
            as: 'coin',
          },
        },
        {
          $unwind: '$coin',
        },
        {
          $lookup: {
            from: 'currencies',
            localField: 'currencyId',
            foreignField: '_id',
            as: 'currency',
          },
        },
        {
          $unwind: '$currency',
        },
        {
          $addFields: {
            displayName: '$coin.symbol' + '/' + '$currency.symbol',
            id: '$_id',
            'coin.id': '$coin._id',
            'currency.id': '$currency._id',
          },
        },
        {
          $project: {
            _id: 0,
            'coin._id': 0,
            'currency._id': 0,
          },
        },
      ]);
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err.message);
    }
  }

  async removeDuplicateCurrencies() {
    try {
      const allCurrencies = await this._currencyModel.find();

      for await (const currency of allCurrencies) {
        const duplicateCurrencies = await this._currencyModel.find({ name: currency.name });
        if (duplicateCurrencies.length > 1) {
          await Promise.all(duplicateCurrencies.slice(1).map(async (duplicateCurrency) => {
            // update user currency to the first currency
            const users = await this._userModel.find({ currencyId: duplicateCurrency?.id });

            await Promise.all(users.map(async (user) => {
              await user.updateOne({ currencyId: duplicateCurrencies?.[0].id });
              console.log('User currency updated', user?.email, duplicateCurrencies?.[0]?.name);
            }));

            await this._currencyModel.deleteOne({ _id: duplicateCurrency.id });
            console.log('Currency deleted', duplicateCurrency?.name);
          }));
        }
      }
    }
    catch (err) {
      console.log(err);
    }
  }

  async addCurrencies() {
    try {
      const coinGeckoCoins = [
        'aed',
        'ars',
        'aud',
        'bch',
        'bdt',
        'bhd',
        'bmd',
        'bnb',
        'brl',
        'btc',
        'cad',
        'chf',
        'clp',
        'cny',
        'czk',
        'dkk',
        'dot',
        'eos',
        'eth',
        'eur',
        'gbp',
        'hkd',
        'huf',
        'idr',
        'ils',
        'inr',
        'jpy',
        'krw',
        'kwd',
        'lkr',
        'ltc',
        'mmk',
        'mxn',
        'myr',
        'ngn',
        'nok',
        'nzd',
        'php',
        'pkr',
        'pln',
        'rub',
        'sar',
        'sek',
        'sgd',
        'thb',
        'try',
        'twd',
        'uah',
        'usd',
        'vef',
        'vnd',
        'xag',
        'xau',
        'xdr',
        'xlm',
        'xrp',
        'yfi',
        'zar',
        'bits',
        'link',
        'sats',
      ];
      const coinsData: {
        symbol: string,
        name: string,
        symbol_native?: string,
        decimal_digits: number,
        rounding: number,
        code: string,
        name_plural: string,
        country: string,
      }[] = [
          {
            symbol: '$',
            name: 'US Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'USD',
            name_plural: 'US dollars',
            country: 'United States',
          },
          {
            symbol: 'CA$',
            name: 'Canadian Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'CAD',
            name_plural: 'Canadian dollars',
            country: 'Canada',
          },
          {
            symbol: '€',
            name: 'Euro',
            symbol_native: '€',
            decimal_digits: 2,
            rounding: 0,
            code: 'EUR',
            name_plural: 'euros',
            country: 'European Union',
          },
          {
            symbol: 'AED',
            name: 'United Arab Emirates Dirham',
            symbol_native: 'د.إ.‏',
            decimal_digits: 2,
            rounding: 0,
            code: 'AED',
            name_plural: 'UAE dirhams',
            country: 'United Arab Emirates',
          },
          {
            symbol: 'Af',
            name: 'Afghan Afghani',
            symbol_native: '؋',
            decimal_digits: 0,
            rounding: 0,
            code: 'AFN',
            name_plural: 'Afghan Afghanis',
            country: 'Afghanistan',
          },
          {
            symbol: 'ALL',
            name: 'Albanian Lek',
            symbol_native: 'Lek',
            decimal_digits: 0,
            rounding: 0,
            code: 'ALL',
            name_plural: 'Albanian lekë',
            country: 'Albania',
          },
          {
            symbol: 'AMD',
            name: 'Armenian Dram',
            symbol_native: 'դր.',
            decimal_digits: 0,
            rounding: 0,
            code: 'AMD',
            name_plural: 'Armenian drams',
            country: 'Armenia',
          },
          {
            symbol: 'AR$',
            name: 'Argentine Peso',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'ARS',
            name_plural: 'Argentine pesos',
            country: 'Argentina',
          },
          {
            symbol: 'AU$',
            name: 'Australian Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'AUD',
            name_plural: 'Australian dollars',
            country: 'Australia',
          },
          {
            symbol: 'man.',
            name: 'Azerbaijani Manat',
            symbol_native: 'ман.',
            decimal_digits: 2,
            rounding: 0,
            code: 'AZN',
            name_plural: 'Azerbaijani manats',
            country: 'Azerbaijan',
          },
          {
            symbol: 'KM',
            name: 'Bosnia-Herzegovina Convertible Mark',
            symbol_native: 'KM',
            decimal_digits: 2,
            rounding: 0,
            code: 'BAM',
            name_plural: 'Bosnia-Herzegovina convertible marks',
            country: 'Bosnia and Herzegovina',
          },
          {
            symbol: 'Tk',
            name: 'Bangladeshi Taka',
            symbol_native: '৳',
            decimal_digits: 2,
            rounding: 0,
            code: 'BDT',
            name_plural: 'Bangladeshi takas',
            country: 'Bangladesh',
          },
          {
            symbol: 'BGN',
            name: 'Bulgarian Lev',
            symbol_native: 'лв.',
            decimal_digits: 2,
            rounding: 0,
            code: 'BGN',
            name_plural: 'Bulgarian leva',
            country: 'Bulgaria',
          },
          {
            symbol: 'BD',
            name: 'Bahraini Dinar',
            symbol_native: 'د.ب.‏',
            decimal_digits: 3,
            rounding: 0,
            code: 'BHD',
            name_plural: 'Bahraini dinars',
            country: 'Bahrain',
          },
          {
            symbol: 'FBu',
            name: 'Burundian Franc',
            symbol_native: 'FBu',
            decimal_digits: 0,
            rounding: 0,
            code: 'BIF',
            name_plural: 'Burundian francs',
            country: 'Burundi',
          },
          {
            symbol: 'BN$',
            name: 'Brunei Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'BND',
            name_plural: 'Brunei dollars',
            country: 'Brunei',
          },
          {
            symbol: 'Bs',
            name: 'Bolivian Boliviano',
            symbol_native: 'Bs',
            decimal_digits: 2,
            rounding: 0,
            code: 'BOB',
            name_plural: 'Bolivian bolivianos',
            country: 'Bolivia',
          },
          {
            symbol: 'R$',
            name: 'Brazilian Real',
            symbol_native: 'R$',
            decimal_digits: 2,
            rounding: 0,
            code: 'BRL',
            name_plural: 'Brazilian reals',
            country: 'Brazil',
          },
          {
            symbol: 'BWP',
            name: 'Botswanan Pula',
            symbol_native: 'P',
            decimal_digits: 2,
            rounding: 0,
            code: 'BWP',
            name_plural: 'Botswanan pulas',
            country: 'Botswana',
          },
          {
            symbol: 'Br',
            name: 'Belarusian Ruble',
            symbol_native: 'руб.',
            decimal_digits: 2,
            rounding: 0,
            code: 'BYN',
            name_plural: 'Belarusian rubles',
            country: 'Belarus',
          },
          {
            symbol: 'BZ$',
            name: 'Belize Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'BZD',
            name_plural: 'Belize dollars',
            country: 'Belize',
          },
          {
            symbol: 'CDF',
            name: 'Congolese Franc',
            symbol_native: 'FrCD',
            decimal_digits: 2,
            rounding: 0,
            code: 'CDF',
            name_plural: 'Congolese francs',
            country: 'Congo - Kinshasa',
          },
          {
            symbol: 'CHF',
            name: 'Swiss Franc',
            symbol_native: 'CHF',
            decimal_digits: 2,
            rounding: 0.05,
            code: 'CHF',
            name_plural: 'Swiss francs',
            country: 'Switzerland',
          },
          {
            symbol: 'CL$',
            name: 'Chilean Peso',
            symbol_native: '$',
            decimal_digits: 0,
            rounding: 0,
            code: 'CLP',
            name_plural: 'Chilean pesos',
            country: 'Chile',
          },
          {
            symbol: 'CN¥',
            name: 'Chinese Yuan',
            symbol_native: 'CN¥',
            decimal_digits: 2,
            rounding: 0,
            code: 'CNY',
            name_plural: 'Chinese yuan',
            country: 'China',
          },
          {
            symbol: 'CO$',
            name: 'Colombian Peso',
            symbol_native: '$',
            decimal_digits: 0,
            rounding: 0,
            code: 'COP',
            name_plural: 'Colombian pesos',
            country: 'Colombia',
          },
          {
            symbol: '₡',
            name: 'Costa Rican Colón',
            symbol_native: '₡',
            decimal_digits: 0,
            rounding: 0,
            code: 'CRC',
            name_plural: 'Costa Rican colóns',
            country: 'Costa Rica',
          },
          {
            symbol: 'CV$',
            name: 'Cape Verdean Escudo',
            symbol_native: 'CV$',
            decimal_digits: 2,
            rounding: 0,
            code: 'CVE',
            name_plural: 'Cape Verdean escudos',
            country: 'Cape Verde',
          },
          {
            symbol: 'Kč',
            name: 'Czech Republic Koruna',
            symbol_native: 'Kč',
            decimal_digits: 2,
            rounding: 0,
            code: 'CZK',
            name_plural: 'Czech Republic korunas',
            country: 'Czech Republic',
          },
          {
            symbol: 'Fdj',
            name: 'Djiboutian Franc',
            symbol_native: 'Fdj',
            decimal_digits: 0,
            rounding: 0,
            code: 'DJF',
            name_plural: 'Djiboutian francs',
            country: 'Djibouti',
          },
          {
            symbol: 'Dkr',
            name: 'Danish Krone',
            symbol_native: 'kr',
            decimal_digits: 2,
            rounding: 0,
            code: 'DKK',
            name_plural: 'Danish kroner',
            country: 'Denmark',
          },
          {
            symbol: 'RD$',
            name: 'Dominican Peso',
            symbol_native: 'RD$',
            decimal_digits: 2,
            rounding: 0,
            code: 'DOP',
            name_plural: 'Dominican pesos',
            country: 'Dominican Republic',
          },
          {
            symbol: 'DA',
            name: 'Algerian Dinar',
            symbol_native: 'د.ج.‏',
            decimal_digits: 2,
            rounding: 0,
            code: 'DZD',
            name_plural: 'Algerian dinars',
            country: 'Algeria',
          },
          {
            symbol: 'Ekr',
            name: 'Estonian Kroon',
            symbol_native: 'kr',
            decimal_digits: 2,
            rounding: 0,
            code: 'EEK',
            name_plural: 'Estonian kroons',
            country: 'Estonia',
          },
          {
            symbol: 'EGP',
            name: 'Egyptian Pound',
            symbol_native: 'ج.م.‏',
            decimal_digits: 2,
            rounding: 0,
            code: 'EGP',
            name_plural: 'Egyptian pounds',
            country: 'Egypt',
          },
          {
            symbol: 'Nfk',
            name: 'Eritrean Nakfa',
            symbol_native: 'Nfk',
            decimal_digits: 2,
            rounding: 0,
            code: 'ERN',
            name_plural: 'Eritrean nakfas',
            country: 'Eritrea',
          },
          {
            symbol: 'Br',
            name: 'Ethiopian Birr',
            symbol_native: 'Br',
            decimal_digits: 2,
            rounding: 0,
            code: 'ETB',
            name_plural: 'Ethiopian birrs',
            country: 'Ethiopia',
          },
          {
            symbol: '£',
            name: 'British Pound Sterling',
            symbol_native: '£',
            decimal_digits: 2,
            rounding: 0,
            code: 'GBP',
            name_plural: 'British pounds sterling',
            country: 'United Kingdom',
          },
          {
            symbol: 'GEL',
            name: 'Georgian Lari',
            symbol_native: 'GEL',
            decimal_digits: 2,
            rounding: 0,
            code: 'GEL',
            name_plural: 'Georgian laris',
            country: 'Georgia',
          },
          {
            symbol: 'GH₵',
            name: 'Ghanaian Cedi',
            symbol_native: 'GH₵',
            decimal_digits: 2,
            rounding: 0,
            code: 'GHS',
            name_plural: 'Ghanaian cedis',
            country: 'Ghana',
          },
          {
            symbol: 'FG',
            name: 'Guinean Franc',
            symbol_native: 'FG',
            decimal_digits: 0,
            rounding: 0,
            code: 'GNF',
            name_plural: 'Guinean francs',
            country: 'Guinea',
          },
          {
            symbol: 'GTQ',
            name: 'Guatemalan Quetzal',
            symbol_native: 'Q',
            decimal_digits: 2,
            rounding: 0,
            code: 'GTQ',
            name_plural: 'Guatemalan quetzals',
            country: 'Guatemala',
          },
          {
            symbol: 'HK$',
            name: 'Hong Kong Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'HKD',
            name_plural: 'Hong Kong dollars',
            country: 'Hong Kong',
          },
          {
            symbol: 'HNL',
            name: 'Honduran Lempira',
            symbol_native: 'L',
            decimal_digits: 2,
            rounding: 0,
            code: 'HNL',
            name_plural: 'Honduran lempiras',
            country: 'Honduras',
          },
          {
            symbol: 'kn',
            name: 'Croatian Kuna',
            symbol_native: 'kn',
            decimal_digits: 2,
            rounding: 0,
            code: 'HRK',
            name_plural: 'Croatian kunas',
            country: 'Croatia',
          },
          {
            symbol: 'Ft',
            name: 'Hungarian Forint',
            symbol_native: 'Ft',
            decimal_digits: 0,
            rounding: 0,
            code: 'HUF',
            name_plural: 'Hungarian forints',
            country: 'Hungary',
          },
          {
            symbol: 'Rp',
            name: 'Indonesian Rupiah',
            symbol_native: 'Rp',
            decimal_digits: 0,
            rounding: 0,
            code: 'IDR',
            name_plural: 'Indonesian rupiahs',
            country: 'Indonesia',
          },
          {
            symbol: '₪',
            name: 'Israeli New Sheqel',
            symbol_native: '₪',
            decimal_digits: 2,
            rounding: 0,
            code: 'ILS',
            name_plural: 'Israeli new sheqels',
            country: "Israel"
          },
          {
            symbol: 'Rs',
            name: 'Indian Rupee',
            symbol_native: 'টকা',
            decimal_digits: 2,
            rounding: 0,
            code: 'INR',
            name_plural: 'Indian rupees',
            country: 'India',
          },
          {
            symbol: 'IQD',
            name: 'Iraqi Dinar',
            symbol_native: 'د.ع.‏',
            decimal_digits: 0,
            rounding: 0,
            code: 'IQD',
            name_plural: 'Iraqi dinars',
            country: 'Iraq',
          },
          {
            symbol: 'IRR',
            name: 'Iranian Rial',
            symbol_native: '﷼',
            decimal_digits: 0,
            rounding: 0,
            code: 'IRR',
            name_plural: 'Iranian rials',
            country: 'Iran',
          },
          {
            symbol: 'Ikr',
            name: 'Icelandic Króna',
            symbol_native: 'kr',
            decimal_digits: 0,
            rounding: 0,
            code: 'ISK',
            name_plural: 'Icelandic krónur',
            country: 'Iceland',
          },
          {
            symbol: 'J$',
            name: 'Jamaican Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'JMD',
            name_plural: 'Jamaican dollars',
            country: 'Jamaica',
          },
          {
            symbol: 'JD',
            name: 'Jordanian Dinar',
            symbol_native: 'د.أ.‏',
            decimal_digits: 3,
            rounding: 0,
            code: 'JOD',
            name_plural: 'Jordanian dinars',
            country: 'Jordan',
          },
          {
            symbol: '¥',
            name: 'Japanese Yen',
            symbol_native: '￥',
            decimal_digits: 0,
            rounding: 0,
            code: 'JPY',
            name_plural: 'Japanese yen',
            country: 'Japan',
          },
          {
            symbol: 'Ksh',
            name: 'Kenyan Shilling',
            symbol_native: 'Ksh',
            decimal_digits: 2,
            rounding: 0,
            code: 'KES',
            name_plural: 'Kenyan shillings',
            country: 'Kenya',
          },
          {
            symbol: 'KHR',
            name: 'Cambodian Riel',
            symbol_native: '៛',
            decimal_digits: 2,
            rounding: 0,
            code: 'KHR',
            name_plural: 'Cambodian riels',
            country: 'Cambodia',
          },
          {
            symbol: 'CF',
            name: 'Comorian Franc',
            symbol_native: 'FC',
            decimal_digits: 0,
            rounding: 0,
            code: 'KMF',
            name_plural: 'Comorian francs',
            country: 'Comoros',
          },
          {
            symbol: '₩',
            name: 'South Korean Won',
            symbol_native: '₩',
            decimal_digits: 0,
            rounding: 0,
            code: 'KRW',
            name_plural: 'South Korean won',
            country: 'South Korea',
          },
          {
            symbol: 'KD',
            name: 'Kuwaiti Dinar',
            symbol_native: 'د.ك.‏',
            decimal_digits: 3,
            rounding: 0,
            code: 'KWD',
            name_plural: 'Kuwaiti dinars',
            country: 'Kuwait',
          },
          {
            symbol: 'KZT',
            name: 'Kazakhstani Tenge',
            symbol_native: 'тңг.',
            decimal_digits: 2,
            rounding: 0,
            code: 'KZT',
            name_plural: 'Kazakhstani tenges',
            country: 'Kazakhstan',
          },
          {
            symbol: 'L.L.',
            name: 'Lebanese Pound',
            symbol_native: 'ل.ل.‏',
            decimal_digits: 0,
            rounding: 0,
            code: 'LBP',
            name_plural: 'Lebanese pounds',
            country: 'Lebanon',
          },
          {
            symbol: 'SLRs',
            name: 'Sri Lankan Rupee',
            symbol_native: 'SL Re',
            decimal_digits: 2,
            rounding: 0,
            code: 'LKR',
            name_plural: 'Sri Lankan rupees',
            country: 'Sri Lanka',
          },
          {
            symbol: 'Lt',
            name: 'Lithuanian Litas',
            symbol_native: 'Lt',
            decimal_digits: 2,
            rounding: 0,
            code: 'LTL',
            name_plural: 'Lithuanian litai',
            country: 'Lithuania',
          },
          {
            symbol: 'Ls',
            name: 'Latvian Lats',
            symbol_native: 'Ls',
            decimal_digits: 2,
            rounding: 0,
            code: 'LVL',
            name_plural: 'Latvian lati',
            country: 'Latvia',
          },
          {
            symbol: 'LD',
            name: 'Libyan Dinar',
            symbol_native: 'د.ل.‏',
            decimal_digits: 3,
            rounding: 0,
            code: 'LYD',
            name_plural: 'Libyan dinars',
            country: 'Libya',
          },
          {
            symbol: 'MAD',
            name: 'Moroccan Dirham',
            symbol_native: 'د.م.‏',
            decimal_digits: 2,
            rounding: 0,
            code: 'MAD',
            name_plural: 'Moroccan dirhams',
            country: 'Morocco',
          },
          {
            symbol: 'MDL',
            name: 'Moldovan Leu',
            symbol_native: 'MDL',
            decimal_digits: 2,
            rounding: 0,
            code: 'MDL',
            name_plural: 'Moldovan lei',
            country: 'Moldova',
          },
          {
            symbol: 'MGA',
            name: 'Malagasy Ariary',
            symbol_native: 'MGA',
            decimal_digits: 0,
            rounding: 0,
            code: 'MGA',
            name_plural: 'Malagasy Ariaries',
            country: 'Madagascar',
          },
          {
            symbol: 'MKD',
            name: 'Macedonian Denar',
            symbol_native: 'MKD',
            decimal_digits: 2,
            rounding: 0,
            code: 'MKD',
            name_plural: 'Macedonian denari',
            country: 'Macedonia',
          },
          {
            symbol: 'MMK',
            name: 'Myanma Kyat',
            symbol_native: 'K',
            decimal_digits: 0,
            rounding: 0,
            code: 'MMK',
            name_plural: 'Myanma kyats',
            country: 'Myanmar [Burma]',
          },
          {
            symbol: 'MOP$',
            name: 'Macanese Pataca',
            symbol_native: 'MOP$',
            decimal_digits: 2,
            rounding: 0,
            code: 'MOP',
            name_plural: 'Macanese patacas',
            country: 'Macau',
          },
          {
            symbol: 'MURs',
            name: 'Mauritian Rupee',
            symbol_native: 'MURs',
            decimal_digits: 0,
            rounding: 0,
            code: 'MUR',
            name_plural: 'Mauritian rupees',
            country: 'Mauritius',
          },
          {
            symbol: 'MX$',
            name: 'Mexican Peso',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'MXN',
            name_plural: 'Mexican pesos',
            country: 'Mexico',
          },
          {
            symbol: 'RM',
            name: 'Malaysian Ringgit',
            symbol_native: 'RM',
            decimal_digits: 2,
            rounding: 0,
            code: 'MYR',
            name_plural: 'Malaysian ringgits',
            country: 'Malaysia',
          },
          {
            symbol: 'MTn',
            name: 'Mozambican Metical',
            symbol_native: 'MTn',
            decimal_digits: 2,
            rounding: 0,
            code: 'MZN',
            name_plural: 'Mozambican meticals',
            country: 'Mozambique',
          },
          {
            symbol: 'N$',
            name: 'Namibian Dollar',
            symbol_native: 'N$',
            decimal_digits: 2,
            rounding: 0,
            code: 'NAD',
            name_plural: 'Namibian dollars',
            country: 'Namibia',
          },
          {
            symbol: '₦',
            name: 'Nigerian Naira',
            symbol_native: '₦',
            decimal_digits: 2,
            rounding: 0,
            code: 'NGN',
            name_plural: 'Nigerian nairas',
            country: 'Nigeria',
          },
          {
            symbol: 'C$',
            name: 'Nicaraguan Córdoba',
            symbol_native: 'C$',
            decimal_digits: 2,
            rounding: 0,
            code: 'NIO',
            name_plural: 'Nicaraguan córdobas',
            country: 'Nicaragua',
          },
          {
            symbol: 'Nkr',
            name: 'Norwegian Krone',
            symbol_native: 'kr',
            decimal_digits: 2,
            rounding: 0,
            code: 'NOK',
            name_plural: 'Norwegian kroner',
            country: 'Norway',
          },
          {
            symbol: 'NPRs',
            name: 'Nepalese Rupee',
            symbol_native: 'नेरू',
            decimal_digits: 2,
            rounding: 0,
            code: 'NPR',
            name_plural: 'Nepalese rupees',
            country: 'Nepal',
          },
          {
            symbol: 'NZ$',
            name: 'New Zealand Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'NZD',
            name_plural: 'New Zealand dollars',
            country: 'New Zealand',
          },
          {
            symbol: 'OMR',
            name: 'Omani Rial',
            symbol_native: 'ر.ع.‏',
            decimal_digits: 3,
            rounding: 0,
            code: 'OMR',
            name_plural: 'Omani rials',
            country: 'Oman',
          },
          {
            symbol: 'B/.',
            name: 'Panamanian Balboa',
            symbol_native: 'B/.',
            decimal_digits: 2,
            rounding: 0,
            code: 'PAB',
            name_plural: 'Panamanian balboas',
            country: 'Panama',
          },
          {
            symbol: 'S/.',
            name: 'Peruvian Nuevo Sol',
            symbol_native: 'S/.',
            decimal_digits: 2,
            rounding: 0,
            code: 'PEN',
            name_plural: 'Peruvian nuevos soles',
            country: 'Peru',
          },
          {
            symbol: '₱',
            name: 'Philippine Peso',
            symbol_native: '₱',
            decimal_digits: 2,
            rounding: 0,
            code: 'PHP',
            name_plural: 'Philippine pesos',
            country: 'Philippines',
          },
          {
            symbol: 'PKRs',
            name: 'Pakistani Rupee',
            symbol_native: '₨',
            decimal_digits: 0,
            rounding: 0,
            code: 'PKR',
            name_plural: 'Pakistani rupees',
            country: 'Pakistan',
          },
          {
            symbol: 'zł',
            name: 'Polish Zloty',
            symbol_native: 'zł',
            decimal_digits: 2,
            rounding: 0,
            code: 'PLN',
            name_plural: 'Polish zlotys',
            country: 'Poland',
          },
          {
            symbol: '₲',
            name: 'Paraguayan Guarani',
            symbol_native: '₲',
            decimal_digits: 0,
            rounding: 0,
            code: 'PYG',
            name_plural: 'Paraguayan guaranis',
            country: 'Paraguay',
          },
          {
            symbol: 'QR',
            name: 'Qatari Rial',
            symbol_native: 'ر.ق.‏',
            decimal_digits: 2,
            rounding: 0,
            code: 'QAR',
            name_plural: 'Qatari rials',
            country: 'Qatar',
          },
          {
            symbol: 'RON',
            name: 'Romanian Leu',
            symbol_native: 'RON',
            decimal_digits: 2,
            rounding: 0,
            code: 'RON',
            name_plural: 'Romanian lei',
            country: 'Romania',
          },
          {
            symbol: 'din.',
            name: 'Serbian Dinar',
            symbol_native: 'дин.',
            decimal_digits: 0,
            rounding: 0,
            code: 'RSD',
            name_plural: 'Serbian dinars',
            country: 'Serbia',
          },
          {
            symbol: 'RUB',
            name: 'Russian Ruble',
            symbol_native: '₽.',
            decimal_digits: 2,
            rounding: 0,
            code: 'RUB',
            name_plural: 'Russian rubles',
            country: 'Russia',
          },
          {
            symbol: 'RWF',
            name: 'Rwandan Franc',
            symbol_native: 'FR',
            decimal_digits: 0,
            rounding: 0,
            code: 'RWF',
            name_plural: 'Rwandan francs',
            country: 'Rwanda',
          },
          {
            symbol: 'SR',
            name: 'Saudi Riyal',
            symbol_native: 'ر.س.‏',
            decimal_digits: 2,
            rounding: 0,
            code: 'SAR',
            name_plural: 'Saudi riyals',
            country: 'Saudi Arabia',
          },
          {
            symbol: 'SDG',
            name: 'Sudanese Pound',
            symbol_native: 'SDG',
            decimal_digits: 2,
            rounding: 0,
            code: 'SDG',
            name_plural: 'Sudanese pounds',
            country: 'Sudan',
          },
          {
            symbol: 'Skr',
            name: 'Swedish Krona',
            symbol_native: 'kr',
            decimal_digits: 2,
            rounding: 0,
            code: 'SEK',
            name_plural: 'Swedish kronor',
            country: 'Sweden',
          },
          {
            symbol: 'S$',
            name: 'Singapore Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'SGD',
            name_plural: 'Singapore dollars',
            country: 'Singapore',
          },
          {
            symbol: 'Ssh',
            name: 'Somali Shilling',
            symbol_native: 'Ssh',
            decimal_digits: 0,
            rounding: 0,
            code: 'SOS',
            name_plural: 'Somali shillings',
            country: 'Somalia',
          },
          {
            symbol: 'SY£',
            name: 'Syrian Pound',
            symbol_native: 'ل.س.‏',
            decimal_digits: 0,
            rounding: 0,
            code: 'SYP',
            name_plural: 'Syrian pounds',
            country: 'Syria',
          },
          {
            symbol: '฿',
            name: 'Thai Baht',
            symbol_native: '฿',
            decimal_digits: 2,
            rounding: 0,
            code: 'THB',
            name_plural: 'Thai baht',
            country: 'Thailand',
          },
          {
            symbol: 'DT',
            name: 'Tunisian Dinar',
            symbol_native: 'د.ت.‏',
            decimal_digits: 3,
            rounding: 0,
            code: 'TND',
            name_plural: 'Tunisian dinars',
            country: 'Tunisia',
          },
          {
            symbol: 'T$',
            name: 'Tongan Paʻanga',
            symbol_native: 'T$',
            decimal_digits: 2,
            rounding: 0,
            code: 'TOP',
            name_plural: 'Tongan paʻanga',
            country: 'Tonga',
          },
          {
            symbol: 'TL',
            name: 'Turkish Lira',
            symbol_native: 'TL',
            decimal_digits: 2,
            rounding: 0,
            code: 'TRY',
            name_plural: 'Turkish Lira',
            country: 'Turkey',
          },
          {
            symbol: 'TT$',
            name: 'Trinidad and Tobago Dollar',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'TTD',
            name_plural: 'Trinidad and Tobago dollars',
            country: 'Trinidad and Tobago',
          },
          {
            symbol: 'NT$',
            name: 'New Taiwan Dollar',
            symbol_native: 'NT$',
            decimal_digits: 2,
            rounding: 0,
            code: 'TWD',
            name_plural: 'New Taiwan dollars',
            country: 'Taiwan',
          },
          {
            symbol: 'TSh',
            name: 'Tanzanian Shilling',
            symbol_native: 'TSh',
            decimal_digits: 0,
            rounding: 0,
            code: 'TZS',
            name_plural: 'Tanzanian shillings',
            country: 'Tanzania',
          },
          {
            symbol: '₴',
            name: 'Ukrainian Hryvnia',
            symbol_native: '₴',
            decimal_digits: 2,
            rounding: 0,
            code: 'UAH',
            name_plural: 'Ukrainian hryvnias',
            country: 'Ukraine',
          },
          {
            symbol: 'USh',
            name: 'Ugandan Shilling',
            symbol_native: 'USh',
            decimal_digits: 0,
            rounding: 0,
            code: 'UGX',
            name_plural: 'Ugandan shillings',
            country: 'Uganda',
          },
          {
            symbol: '$U',
            name: 'Uruguayan Peso',
            symbol_native: '$',
            decimal_digits: 2,
            rounding: 0,
            code: 'UYU',
            name_plural: 'Uruguayan pesos',
            country: 'Uruguay',
          },
          {
            symbol: 'UZS',
            name: 'Uzbekistan Som',
            symbol_native: 'UZS',
            decimal_digits: 0,
            rounding: 0,
            code: 'UZS',
            name_plural: 'Uzbekistan som',
            country: 'Uzbekistan',
          },
          {
            symbol: 'Bs.F.',
            name: 'Venezuelan Bolívar',
            symbol_native: 'Bs.F.',
            decimal_digits: 2,
            rounding: 0,
            code: 'VEF',
            name_plural: 'Venezuelan bolívars',
            country: 'Venezuela',
          },
          {
            symbol: '₫',
            name: 'Vietnamese Dong',
            symbol_native: '₫',
            decimal_digits: 0,
            rounding: 0,
            code: 'VND',
            name_plural: 'Vietnamese dong',
            country: 'Vietnam',
          },
          {
            symbol: 'FCFA',
            name: 'CFA Franc BEAC',
            symbol_native: 'FCFA',
            decimal_digits: 0,
            rounding: 0,
            code: 'XAF',
            name_plural: 'CFA francs BEAC',
            country: 'Cameroon',
          },
          {
            symbol: 'CFA',
            name: 'CFA Franc BCEAO',
            symbol_native: 'CFA',
            decimal_digits: 0,
            rounding: 0,
            code: 'XOF',
            name_plural: 'CFA francs BCEAO',
            country: 'Senegal',
          },
          {
            symbol: 'YR',
            name: 'Yemeni Rial',
            symbol_native: 'ر.ي.‏',
            decimal_digits: 0,
            rounding: 0,
            code: 'YER',
            name_plural: 'Yemeni rials',
            country: 'Yemen',
          },
          {
            symbol: 'R',
            name: 'South African Rand',
            symbol_native: 'R',
            decimal_digits: 2,
            rounding: 0,
            code: 'ZAR',
            name_plural: 'South African rand',
            country: 'South Africa',
          },
          {
            symbol: 'ZK',
            name: 'Zambian Kwacha',
            symbol_native: 'ZK',
            decimal_digits: 0,
            rounding: 0,
            code: 'ZMK',
            name_plural: 'Zambian kwachas',
            country: 'Zambia',
          },
          {
            symbol: 'ZWL$',
            name: 'Zimbabwean Dollar',
            symbol_native: 'ZWL$',
            decimal_digits: 0,
            rounding: 0,
            code: 'ZWL',
            name_plural: 'Zimbabwean Dollar',
            country: 'Zimbabwe',
          },
        ];

      await Promise.all(
        coinGeckoCoins.map(async (coin) => {
          const isCurrencyExists = await this._currencyModel.findOne({
            coinGeckoId: coin,
          });

          if (!isCurrencyExists) {
            const coinData = coinsData?.find(
              (coinData) => coinData.code?.toLowerCase() === coin,
            );

            if (!coinData) {
              return;
            }

            const currency = new this._currencyModel({
              name: coinData?.name,
              symbol: coinData?.symbol,
              coinGeckoId: coin,
              logoUrl: '',
              isDeleted: false,
              isActive: true,
              country: coinData?.country,
            }).save();

            return currency;
          }
        }),
      );
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err.message);
    }
  }

  async getInvestmentDataForAllUsers(userIds: string[] = []) {
    try {
      const query = {}
      if (userIds.length > 0) {
        query['_id'] = { $in: userIds };
      }

      const users = await this._userModel.aggregate([
        {
          $match: query,
        },
        {
          $lookup: {
            from: 'wallets',
            localField: '_id',
            foreignField: 'userId',
            as: 'wallet',
          },
        },
        {
          $unwind: '$wallet',
        },
        {
          $addFields: {
            id: '$_id',
            walletId: '$wallet._id',
          },
        },
        {
          $project: {
            _id: 0,
            'wallet._id': 0,
          },
        },
      ]);

      for await (const user of users) {
        await this.getUserInvestmentData(user);
      }

    }
    catch (err) {
      console.log(err);
      throw new BadRequestException(err.message);
    }
  }

  async getUserInvestmentData(user) {
    try {
      const coins = await this._coinModel.aggregate([
        {
          $match: {
            isDeleted: false,
            isActive: true,
            isStakingAvailable: true,
          },
        },
        {
          $lookup: {
            from: 'networks',
            localField: 'networkId',
            foreignField: '_id',
            as: 'network',
          },
        },
        {
          $unwind: '$network',
        },
        {
          $addFields: {
            id: '$_id',
            networkId: '$network._id',
          }
        },
        {
          $project: {
            _id: 0,
            'network._id': 0,
          },
        },
      ]);

      for await (const coin of coins) {
        const stakingService = new StakeService(coin?.stakingContractAddress, coin?.network?.rpcUrl, coin?.contractAddress);

        const userStakingData = await stakingService?.getUserStakingInformation(user?.wallet?.evmAddress);

        await this._userStakeInfoModel.updateOne({
          userId: user?.id,
          coinId: coin?.id
        }, {
          totalInvestments: userStakingData?.totalInvestments,
          totalStaked: userStakingData?.totalStaked,
          totalRewards: userStakingData?.totalRewards,
          investmentIds: userStakingData?.investmentIds,
          stakingContractAddress: coin?.stakingContractAddress,
        }, {
          upsert: true
        })


      }

    }
    catch (err) {
      console.log(err);
      throw new Error(err.message);
    }
  }

  async getAllInvestmentDataForInvestmentIds(investmentIds: number[] = [], coinId: string) {
    try {
      const coin = await this._coinModel.aggregate([
        {
          $match: {
            _id: coinId,
            isDeleted: false,
            isActive: true,
            isStakingAvailable: true,
          },
        },
        {
          $lookup: {
            from: 'networks',
            localField: 'networkId',
            foreignField: '_id',
            as: 'network',
          },
        },
        {
          $unwind: '$network',
        },
        {
          $addFields: {
            id: '$_id',
            networkId: '$network._id',
          }
        },
        {
          $project: {
            _id: 0,
            'network._id': 0,
          },
        },
      ])?.then((data) => data?.[0]);

      if (!coin) {
        throw new Error('Coin not found');
      }

      const stakingService = new StakeService(coin?.stakingContractAddress, coin?.network?.rpcUrl, coin?.contractAddress);

      const userStakingData = await stakingService?.getStakingInformations(investmentIds);

      const uniqueWallets = [...new Set(userStakingData.map(item => item?.investor))];

      const wallets = await this._walletModel.find({
        evmAddress: { $in: uniqueWallets },
      })?.lean();

      const userStakingDataWithUserId = userStakingData.map((item) => {
        const wallet = wallets?.find((wallet) => wallet?.evmAddress === item?.investor);

        return {
          ...item,
          userId: wallet?.userId,
        };
      });
      debugger
      const batch = this._stakeInvestmentInfoModel.collection.initializeUnorderedBulkOp();
      debugger
      for (const data of userStakingDataWithUserId) {
        batch.find({
          userId: data?.userId,
          coinId: coin?.id,
          investmentId: Number(data?.id),
        }).upsert().updateOne({
          $set: {
            userAddress: data?.investor?.toLowerCase(),
            stakingContractAddress: data?.stakingContractAddress?.toLowerCase(),
            investmentId: Number(data?.id),
            planId: Number(data?.planId),
            amount: Number(data?.amount),
            startDate: data?.startDate,
            endDate: data?.endDate,
            isClaimed: data?.isClaimed,
            isWithdrawn: data?.isWithdrawn,
            totalReward: Number(data?.totalReward),
            dailyReward: Number(data?.dailyReward),
          }
        });
      }

      await batch.execute()?.catch(err => { });

    }
    catch (err) {
      console.log(err);

    }
  }

  async getAllInvestmentData(startInvestmentIndex: number = 1) {
    try {
      const coins = await this._coinModel.aggregate([
        {
          $match: {
            isDeleted: false,
            isActive: true,
            isStakingAvailable: true,
          },
        },
        {
          $lookup: {
            from: 'networks',
            localField: 'networkId',
            foreignField: '_id',
            as: 'network',
          },
        },
        {
          $unwind: '$network',
        },
        {
          $addFields: {
            id: '$_id',
            networkId: '$network._id',
          }
        },
        {
          $project: {
            _id: 0,
            'network._id': 0,
          },
        },
      ]);

      for await (const coin of coins) {
        const stakingService = new StakeService(coin?.stakingContractAddress, coin?.network?.rpcUrl, coin?.contractAddress);

        let userStakingData = await stakingService?.getAllStakingInformation(startInvestmentIndex);

        const uniqueWallets = [...new Set(userStakingData.map(item => item?.investor))];

        const wallets = await this._walletModel.find({
          evmAddress: { $in: uniqueWallets },
        })?.lean();

        userStakingData = userStakingData.map((item) => {
          const wallet = wallets?.find((wallet) => wallet?.evmAddress === item?.investor);

          return {
            ...item,
            userId: wallet?.userId,
          };
        });
        const batch = this._stakeInvestmentInfoModel.collection.initializeUnorderedBulkOp();

        for (const data of userStakingData) {
          batch.find({
            userId: data?.userId,
            coinId: coin?.id,
            investmentId: Number(data?.id),
          }).upsert().updateOne({
            $set: {
              userAddress: data?.investor?.toLowerCase(),
              stakingContractAddress: data?.stakingContractAddress?.toLowerCase(),
              investmentId: Number(data?.id),
              planId: Number(data?.planId),
              amount: Number(data?.amount),
              startDate: data?.startDate,
              endDate: data?.endDate,
              isClaimed: data?.isClaimed,
              isWithdrawn: data?.isWithdrawn,
              totalReward: Number(data?.totalReward),
              dailyReward: Number(data?.dailyReward),
            }
          });
        }

        await batch.execute()?.catch(err => { });
      }
    }
    catch (err) {
      console.log(err);
      throw new BadRequestException(err.message);
    }
  }
}
