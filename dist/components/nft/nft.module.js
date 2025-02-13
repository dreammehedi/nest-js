"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NftModule = void 0;
const common_1 = require("@nestjs/common");
const nft_controller_1 = require("./nft.controller");
const nft_service_1 = require("./nft.service");
const mongoose_1 = require("@nestjs/mongoose");
const nft_schema_1 = require("../../schema/Nft/nft.schema");
const wallet_schema_1 = require("../../schema/Wallet/wallet.schema");
const network_schema_1 = require("../../schema/Network/network.schema");
const user_schema_1 = require("../../schema/User/user.schema");
let NftModule = class NftModule {
};
exports.NftModule = NftModule;
exports.NftModule = NftModule = __decorate([
    (0, common_1.Module)({
        imports: [
            mongoose_1.MongooseModule.forFeature([
                { name: nft_schema_1.NFT.name, schema: nft_schema_1.NFTSchema },
                { name: network_schema_1.Network.name, schema: network_schema_1.NetworkSchema },
                { name: wallet_schema_1.Wallet.name, schema: wallet_schema_1.WalletSchema },
                { name: user_schema_1.User.name, schema: user_schema_1.UserSchema },
            ]),
        ],
        controllers: [nft_controller_1.NftController],
        providers: [nft_service_1.NftService],
        exports: [nft_service_1.NftService],
    })
], NftModule);
//# sourceMappingURL=nft.module.js.map