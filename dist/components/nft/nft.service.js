"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NftService = void 0;
const common_1 = require("@nestjs/common");
const mongoose_1 = require("@nestjs/mongoose");
const schedule_1 = require("@nestjs/schedule");
const mongoose_2 = require("mongoose");
const moralis_1 = require("moralis");
const network_schema_1 = require("../../schema/Network/network.schema");
const nft_schema_1 = require("../../schema/Nft/nft.schema");
const user_schema_1 = require("../../schema/User/user.schema");
const wallet_schema_1 = require("../../schema/Wallet/wallet.schema");
let NftService = class NftService {
    constructor(nftModel, networkModel, walletModel, userModel) {
        this.nftModel = nftModel;
        this.networkModel = networkModel;
        this.walletModel = walletModel;
        this.userModel = userModel;
    }
    async getAllNftFromWallet(wallet, network, user) {
        try {
            try {
                await moralis_1.default.start({
                    apiKey: process.env.MORALIS_API_KEY,
                });
            }
            catch (err) { }
            const walletAddress = wallet?.evmAddress;
            const networkChain = `0x${network?.chainId.toString(16)}`;
            let response = await moralis_1.default.EvmApi.nft.getWalletNFTs({
                chain: networkChain,
                format: 'decimal',
                mediaItems: true,
                address: walletAddress,
            });
            const nftTokenIds = [];
            do {
                const result = JSON.parse(JSON.stringify(response.getResult()));
                if (result?.length) {
                    const nfts = result?.map((nft) => {
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
                    await Promise.all(nfts.map(async (nft) => {
                        await this.nftModel.updateOne({
                            tokenId: nft.tokenId,
                            contractAddress: nft.contractAddress?.toLowerCase(),
                        }, nft, { upsert: true });
                        nftTokenIds.push({
                            tokenId: nft?.tokenId,
                            contractAddress: nft?.contractAddress?.toLowerCase(),
                        });
                    }));
                }
                if (response.hasNext()) {
                    response = response.next();
                }
                else {
                    break;
                }
            } while (response?.getResult().length > 0);
            if (nftTokenIds.length > 0) {
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
                await Promise.all(nftTokenIdsNotInListObject.map(async (nft) => {
                    await this.nftModel.deleteOne({
                        tokenId: nft.tokenId,
                        contractAddress: nft.contractAddress,
                        walletId: wallet?.id,
                    });
                }));
            }
            return response;
        }
        catch (err) {
            console.log(err);
            throw err;
        }
    }
    async readNftForAllUsers() {
        try {
            const networks = await this.networkModel.find({
                networkType: 'EVM',
            });
            const wallets = await this.walletModel.find({});
            await Promise.all(wallets.map(async (wallet) => {
                const userData = await this.userModel.findOne({
                    _id: wallet?.userId,
                });
                await Promise.all(networks.map(async (network) => {
                    await this.getAllNftFromWallet(wallet, network, userData);
                }));
            }));
        }
        catch (err) {
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
            await Promise.all(wallets.map(async (wallet) => {
                const userData = await this.userModel.findOne({
                    _id: wallet?.userId,
                });
                await Promise.all(networks.map(async (network) => {
                    await this.getAllNftFromWallet(wallet, network, userData);
                }));
            }));
        }
        catch (err) {
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
        }
        catch (err) {
            console.log(err);
            throw new common_1.BadRequestException(err);
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
        }
        catch (err) {
            console.log(err);
            throw new common_1.BadRequestException(err);
        }
    }
};
exports.NftService = NftService;
__decorate([
    (0, schedule_1.Cron)('0 */30 * * * *'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], NftService.prototype, "readNftForAllUsers", null);
exports.NftService = NftService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_1.InjectModel)(nft_schema_1.NFT.name)),
    __param(1, (0, mongoose_1.InjectModel)(network_schema_1.Network.name)),
    __param(2, (0, mongoose_1.InjectModel)(wallet_schema_1.Wallet.name)),
    __param(3, (0, mongoose_1.InjectModel)(user_schema_1.User.name)),
    __metadata("design:paramtypes", [mongoose_2.Model,
        mongoose_2.Model,
        mongoose_2.Model,
        mongoose_2.Model])
], NftService);
//# sourceMappingURL=nft.service.js.map