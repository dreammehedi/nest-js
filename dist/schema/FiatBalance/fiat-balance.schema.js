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
exports.FiatBalanceSchema = exports.FiatBalance = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const utils_1 = require("../../utils/utils");
const user_schema_1 = require("../User/user.schema");
const currency_schema_1 = require("../Currency/currency.schema");
const wallet_schema_1 = require("../Wallet/wallet.schema");
let FiatBalance = class FiatBalance {
};
exports.FiatBalance = FiatBalance;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], FiatBalance.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: user_schema_1.User.name }),
    __metadata("design:type", String)
], FiatBalance.prototype, "userId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: wallet_schema_1.Wallet.name }),
    __metadata("design:type", String)
], FiatBalance.prototype, "walletId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: currency_schema_1.Currency.name }),
    __metadata("design:type", String)
], FiatBalance.prototype, "currencyId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], FiatBalance.prototype, "balance", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], FiatBalance.prototype, "totalWithdrawnAmount", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], FiatBalance.prototype, "totalWithdrawnAmountLocked", void 0);
exports.FiatBalance = FiatBalance = __decorate([
    (0, mongoose_1.Schema)()
], FiatBalance);
exports.FiatBalanceSchema = mongoose_1.SchemaFactory.createForClass(FiatBalance);
exports.FiatBalanceSchema.set('timestamps', true);
exports.FiatBalanceSchema.set('toJSON', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});
exports.FiatBalanceSchema.set('toObject', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});
exports.FiatBalanceSchema.index({ userId: 1 });
exports.FiatBalanceSchema.index({ currencyId: 1 });
exports.FiatBalanceSchema.index({ balance: 1 });
exports.FiatBalanceSchema.index({ userId: 1, currencyId: 1 });
exports.FiatBalanceSchema.index({ userId: 1, balance: 1 });
//# sourceMappingURL=fiat-balance.schema.js.map