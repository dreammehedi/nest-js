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
Object.defineProperty(exports, "__esModule", { value: true });
exports.NFTSchema = exports.NFT = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const utils_1 = require("../../utils/utils");
let NFT = class NFT {
};
exports.NFT = NFT;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], NFT.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "name", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "symbol", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "tokenId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "walletId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "userId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "owner", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, enum: ['ERC721', 'ERC1155'], default: 'ERC721' }),
    __metadata("design:type", String)
], NFT.prototype, "type", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "networkId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "tokenUri", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "contractAddress", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 1 }),
    __metadata("design:type", Number)
], NFT.prototype, "amount", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], NFT.prototype, "imageUrl", void 0);
exports.NFT = NFT = __decorate([
    (0, mongoose_1.Schema)()
], NFT);
exports.NFTSchema = mongoose_1.SchemaFactory.createForClass(NFT);
exports.NFTSchema.set('timestamps', true);
exports.NFTSchema.set('toJSON', {
    transform: function (_, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
        return ret;
    },
});
exports.NFTSchema.set('toObject', {
    transform: function (_, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
        return ret;
    },
});
exports.NFTSchema.index({ name: 1 });
exports.NFTSchema.index({ symbol: 1 });
exports.NFTSchema.index({ tokenId: 1 });
exports.NFTSchema.index({ owner: 1 });
exports.NFTSchema.index({ type: 1 });
exports.NFTSchema.index({ networkId: 1 });
exports.NFTSchema.index({ contractAddress: 1 });
exports.NFTSchema.index({ amount: 1 });
exports.NFTSchema.index({ createdAt: 1 });
exports.NFTSchema.index({ updatedAt: 1 });
exports.NFTSchema.index({ name: 1, symbol: 1 });
exports.NFTSchema.index({ tokenId: 1, owner: 1 });
exports.NFTSchema.index({ networkId: 1, contractAddress: 1 });
exports.NFTSchema.index({ networkId: 1, contractAddress: 1, tokenId: 1 });
exports.NFTSchema.index({ networkId: 1, contractAddress: 1, tokenId: 1, owner: 1 });
exports.NFTSchema.index({
    networkId: 1,
    contractAddress: 1,
    tokenId: 1,
    owner: 1,
    amount: 1,
});
exports.NFTSchema.index({ networkId: 1, contractAddress: 1, tokenId: 1, amount: 1 });
exports.NFTSchema.index({
    networkId: 1,
    contractAddress: 1,
    tokenId: 1,
    amount: 1,
    owner: 1,
});
exports.NFTSchema.index({
    networkId: 1,
    contractAddress: 1,
    tokenId: 1,
    amount: 1,
    owner: 1,
    type: 1,
});
exports.NFTSchema.index({
    networkId: 1,
    contractAddress: 1,
    tokenId: 1,
    amount: 1,
    owner: 1,
    type: 1,
    symbol: 1,
});
exports.NFTSchema.index({
    networkId: 1,
    contractAddress: 1,
    tokenId: 1,
    amount: 1,
    owner: 1,
    type: 1,
    symbol: 1,
    name: 1,
});
exports.NFTSchema.index({
    networkId: 1,
    contractAddress: 1,
    tokenId: 1,
    amount: 1,
    owner: 1,
    type: 1,
    symbol: 1,
    name: 1,
    createdAt: 1,
});
exports.NFTSchema.index({
    networkId: 1,
    contractAddress: 1,
    tokenId: 1,
    amount: 1,
    owner: 1,
    type: 1,
    symbol: 1,
    name: 1,
    createdAt: 1,
    updatedAt: 1,
});
exports.NFTSchema.index({
    networkId: 1,
    contractAddress: 1,
    tokenId: 1,
    amount: 1,
    owner: 1,
    type: 1,
    symbol: 1,
    name: 1,
    createdAt: 1,
    updatedAt: 1,
    isDeleted: 1,
});
//# sourceMappingURL=nft.schema.js.map