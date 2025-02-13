import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Cron } from '@nestjs/schedule';
import axios from 'axios';
import { Model } from 'mongoose';
import Moralis from 'moralis';
import { Network, NetworkDocument } from 'src/schema/Network/network.schema';
import { NFT, NFTDocument } from 'src/schema/Nft/nft.schema';
import { User, UserDocument } from 'src/schema/User/user.schema';
import { Wallet, WalletDocument } from 'src/schema/Wallet/wallet.schema';

@Injectable()
export class NftService {
  constructor(
    @InjectModel(NFT.name) private readonly nftModel: Model<NFTDocument>,
    @InjectModel(Network.name)
    private readonly networkModel: Model<NetworkDocument>,
    @InjectModel(Wallet.name)
    private readonly walletModel: Model<WalletDocument>,
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {
  }

  async getAllNftFromWallet(
    wallet: WalletDocument,
    network: NetworkDocument,
    user: UserDocument,
  ) {
    try {
      // read nft from moralis
      // string number to hex
      try {
        await Moralis.start({
          apiKey: process.env.MORALIS_API_KEY,
        });
      } catch (err) { }

      const walletAddress = wallet?.evmAddress;
      const networkChain = `0x${network?.chainId.toString(16)}`;

      let response: any = await Moralis.EvmApi.nft.getWalletNFTs({
        chain: networkChain,
        format: 'decimal',
        mediaItems: true,
        address: walletAddress,
      });

      const nftTokenIds = [];

      do {
        const result = JSON.parse(JSON.stringify(response.getResult()));
        if (result?.length) {
          const nfts: NFTDocument[] = result?.map((nft: any) => {
            return {
              name: nft?.name,
              symbol: nft?.symbol,
              tokenId: nft?.tokenId,
              walletId: wallet?.id,
              userId: user?.id,
              owner: nft?.ownerOf,
              type: nft?.contractType,
              networkId: network?.id,
              tokenUri: nft?.tokenUri,
              contractAddress: nft?.tokenAddress?.toLowerCase(),
              amount: nft?.amount,
              imageUrl: nft?.media?.originalMediaUrl,
            };
          });

          await Promise.all(
            nfts.map(async (nft) => {
              await this.nftModel.updateOne(
                {
                  tokenId: nft.tokenId,
                  contractAddress: nft.contractAddress?.toLowerCase(),
                },
                nft,
                { upsert: true },
              );

              nftTokenIds.push({
                tokenId: nft?.tokenId,
                contractAddress: nft?.contractAddress?.toLowerCase(),
              });
            }),
          );
        }

        if (response.hasNext()) {
          response = response.next();
        } else {
          break;
        }
      } while (response?.getResult().length > 0);

      if (nftTokenIds.length > 0) {
        // get nft that is not the list
        const allNfts = await this.nftModel.find({
          walletId: wallet?.id,
          networkId: network?.id,
        });

        const nftTokenIdsString = nftTokenIds.map((nft) => {
          return `${nft.tokenId}-${nft.contractAddress}`;
        });

        const allNftsString = allNfts.map((nft) => {
          return `${nft.tokenId}-${nft.contractAddress}`;
        });

        const nftTokenIdsNotInList = allNftsString.filter((nft) => {
          return !nftTokenIdsString.includes(nft);
        });

        const nftTokenIdsNotInListObject = nftTokenIdsNotInList.map((nft) => {
          const nftArray = nft.split('-');
          return {
            tokenId: nftArray[0],
            contractAddress: nftArray[1],
          };
        });

        await Promise.all(
          nftTokenIdsNotInListObject.map(async (nft) => {
            await this.nftModel.deleteOne({
              tokenId: nft.tokenId,
              contractAddress: nft.contractAddress,
              walletId: wallet?.id,
            });
          }),
        );
      }

      return response;
    } catch (err) {
      console.log(err);
      throw err;
    }
  }

  // @Cron('0 0 * * *')
  // cron every 30 minutes
  @Cron('0 */30 * * * *')
  async readNftForAllUsers() {
    try {
      const networks = await this.networkModel.find({
        networkType: 'EVM',
      });

      const wallets = await this.walletModel.find({});

      await Promise.all(
        wallets.map(async (wallet) => {
          const userData = await this.userModel.findOne({
            _id: wallet?.userId,
          });
          await Promise.all(
            networks.map(async (network) => {
              await this.getAllNftFromWallet(wallet, network, userData);
            }),
          );
        }),
      );
    } catch (err) {
      console.log(err);
      throw err;
    }
  }

  async readNftForUser(userId) {
    try {
      const networks = await this.networkModel.find({
        networkType: 'EVM',
      });

      const wallets = await this.walletModel.find({
        userId: userId,
      });

      await Promise.all(
        wallets.map(async (wallet) => {
          const userData = await this.userModel.findOne({
            _id: wallet?.userId,
          });
          await Promise.all(
            networks.map(async (network) => {
              await this.getAllNftFromWallet(wallet, network, userData);
            }),
          );
        }),
      );
    } catch (err) {
      console.log(err);
      throw err;
    }
  }

  async getNfts(limit, offset, user) {
    try {
      limit = limit ? Number(limit) : 10;
      offset = offset ? Number(offset) : 0;

      const nfts = await this.nftModel.aggregate([
        {
          $match: {
            userId: user?.id,
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
      return nfts;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err);
    }
  }

  async getNftById(id) {
    try {
      const nft = await this.nftModel
        .aggregate([
          {
            $match: {
              _id: id,
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
        ])
        .then((nft) => nft[0]);
      return nft;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err);
    }
  }
}
