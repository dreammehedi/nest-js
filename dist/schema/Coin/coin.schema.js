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
exports.CoinSchema = exports.Coin = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const utils_1 = require("../../utils/utils");
const network_schema_1 = require("../Network/network.schema");
let Coin = class Coin {
};
exports.Coin = Coin;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], Coin.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Coin.prototype, "name", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Coin.prototype, "symbol", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Coin.prototype, "icon", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Coin.prototype, "coinNameId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], Coin.prototype, "isToken", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], Coin.prototype, "isStakingAvailable", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Coin.prototype, "contractAddress", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Coin.prototype, "stakingContractAddress", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 18 }),
    __metadata("design:type", Number)
], Coin.prototype, "decimal", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Coin.prototype, "priceMarket", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Coin.prototype, "priceFormer", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Coin.prototype, "price", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Coin.prototype, "priceChange", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Coin.prototype, "swapFee", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: network_schema_1.Network.name }),
    __metadata("design:type", String)
], Coin.prototype, "networkId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], Coin.prototype, "isDeleted", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: true }),
    __metadata("design:type", Boolean)
], Coin.prototype, "isActive", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Coin.prototype, "sort", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Coin.prototype, "unit", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Coin.prototype, "onRampId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Coin.prototype, "onRampNetworkId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', enum: ['COINGECKO', 'COINGECKO_TERMINAL'] }),
    __metadata("design:type", String)
], Coin.prototype, "priceFrom", void 0);
exports.Coin = Coin = __decorate([
    (0, mongoose_1.Schema)()
], Coin);
exports.CoinSchema = mongoose_1.SchemaFactory.createForClass(Coin);
exports.CoinSchema.set('toJSON', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret.__v;
        delete ret._id;
    },
});
exports.CoinSchema.set('toObject', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret.__v;
        delete ret._id;
    },
});
exports.CoinSchema.set('timestamps', true);
exports.CoinSchema.index({ networkId: 1, isDeleted: 1, isActive: 1 });
exports.CoinSchema.index({ networkId: 1, isDeleted: 1, isActive: 1, name: 1 });
exports.CoinSchema.index({ networkId: 1, isDeleted: 1, isActive: 1, symbol: 1 });
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    contractAddress: 1,
});
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    name: 1,
    symbol: 1,
});
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    name: 1,
    contractAddress: 1,
});
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    symbol: 1,
    contractAddress: 1,
});
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    name: 1,
    symbol: 1,
    contractAddress: 1,
});
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    name: 1,
    symbol: 1,
    contractAddress: 1,
    decimal: 1,
});
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    name: 1,
    symbol: 1,
    contractAddress: 1,
    decimal: 1,
    price: 1,
});
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    name: 1,
    symbol: 1,
    contractAddress: 1,
    decimal: 1,
    price: 1,
    isToken: 1,
});
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    name: 1,
    symbol: 1,
    contractAddress: 1,
    decimal: 1,
    price: 1,
    isToken: 1,
    icon: 1,
});
exports.CoinSchema.index({
    networkId: 1,
    isDeleted: 1,
    isActive: 1,
    name: 1,
    symbol: 1,
    contractAddress: 1,
    decimal: 1,
    price: 1,
    isToken: 1,
    icon: 1,
    _id: 1,
});
//# sourceMappingURL=coin.schema.js.map