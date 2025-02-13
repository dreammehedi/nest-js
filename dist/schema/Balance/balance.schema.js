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
exports.BalanceSchema = exports.Balance = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const user_schema_1 = require("../User/user.schema");
const coin_schema_1 = require("../Coin/coin.schema");
const network_schema_1 = require("../Network/network.schema");
const wallet_schema_1 = require("../Wallet/wallet.schema");
const utils_1 = require("../../utils/utils");
let Balance = class Balance {
};
exports.Balance = Balance;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], Balance.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Balance.prototype, "address", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: user_schema_1.User.name }),
    __metadata("design:type", String)
], Balance.prototype, "userId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: wallet_schema_1.Wallet.name }),
    __metadata("design:type", String)
], Balance.prototype, "walletId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: coin_schema_1.Coin.name }),
    __metadata("design:type", String)
], Balance.prototype, "coinId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: network_schema_1.Network.name }),
    __metadata("design:type", String)
], Balance.prototype, "networkId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Balance.prototype, "balance", void 0);
exports.Balance = Balance = __decorate([
    (0, mongoose_1.Schema)()
], Balance);
exports.BalanceSchema = mongoose_1.SchemaFactory.createForClass(Balance);
exports.BalanceSchema.set('toJSON', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});
exports.BalanceSchema.set('toObject', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});
exports.BalanceSchema.set('timestamps', true);
exports.BalanceSchema.index({ userId: 1 });
exports.BalanceSchema.index({ walletId: 1 });
exports.BalanceSchema.index({ coinId: 1 });
exports.BalanceSchema.index({ networkId: 1 });
exports.BalanceSchema.index({ balance: 1 });
exports.BalanceSchema.index({ balanceInUsd: 1 });
exports.BalanceSchema.index({ createdAt: 1 });
exports.BalanceSchema.index({ updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1 });
exports.BalanceSchema.index({ userId: 1, balance: 1 });
exports.BalanceSchema.index({ userId: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, coinId: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, networkId: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, balance: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, networkId: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, balance: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, balance: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, balance: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, balance: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, balance: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, balanceInUsd: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, balanceInUsd: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, createdAt: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, coinId: 1, networkId: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, coinId: 1, balance: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, coinId: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, coinId: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, coinId: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, networkId: 1, balance: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, networkId: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, networkId: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, networkId: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, balance: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, balance: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, balance: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, balanceInUsd: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, balanceInUsd: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, Wallet: 1, createdAt: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, networkId: 1, balance: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, networkId: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, networkId: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, networkId: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, balance: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, balance: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, balance: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, balanceInUsd: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, balanceInUsd: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, coinId: 1, createdAt: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, balance: 1, balanceInUsd: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, balance: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, balance: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, balanceInUsd: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, balanceInUsd: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, networkId: 1, createdAt: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, balance: 1, balanceInUsd: 1, createdAt: 1 });
exports.BalanceSchema.index({ userId: 1, balance: 1, balanceInUsd: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, balance: 1, createdAt: 1, updatedAt: 1 });
exports.BalanceSchema.index({ userId: 1, balanceInUsd: 1, createdAt: 1, updatedAt: 1 });
//# sourceMappingURL=balance.schema.js.map