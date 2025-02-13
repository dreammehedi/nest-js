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
exports.StakeInvestmentInfoSchema = exports.StakeInvestmentInfo = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const user_decorator_1 = require("../../decorators/user.decorator");
const utils_1 = require("../../utils/utils");
const wallet_schema_1 = require("../Wallet/wallet.schema");
const coin_schema_1 = require("../Coin/coin.schema");
let StakeInvestmentInfo = class StakeInvestmentInfo {
};
exports.StakeInvestmentInfo = StakeInvestmentInfo;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], StakeInvestmentInfo.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: user_decorator_1.User.name }),
    __metadata("design:type", String)
], StakeInvestmentInfo.prototype, "userId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: coin_schema_1.Coin.name }),
    __metadata("design:type", String)
], StakeInvestmentInfo.prototype, "coinId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: wallet_schema_1.Wallet.name }),
    __metadata("design:type", String)
], StakeInvestmentInfo.prototype, "walletId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], StakeInvestmentInfo.prototype, "userAddress", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], StakeInvestmentInfo.prototype, "stakingContractAddress", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], StakeInvestmentInfo.prototype, "investmentId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], StakeInvestmentInfo.prototype, "planId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], StakeInvestmentInfo.prototype, "amount", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Date, default: Date.now }),
    __metadata("design:type", Date)
], StakeInvestmentInfo.prototype, "startDate", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Date, default: Date.now }),
    __metadata("design:type", Date)
], StakeInvestmentInfo.prototype, "endDate", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], StakeInvestmentInfo.prototype, "isClaimed", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], StakeInvestmentInfo.prototype, "isWithdrawn", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], StakeInvestmentInfo.prototype, "dailyReward", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], StakeInvestmentInfo.prototype, "totalReward", void 0);
exports.StakeInvestmentInfo = StakeInvestmentInfo = __decorate([
    (0, mongoose_1.Schema)()
], StakeInvestmentInfo);
exports.StakeInvestmentInfoSchema = mongoose_1.SchemaFactory.createForClass(StakeInvestmentInfo);
exports.StakeInvestmentInfoSchema.set('timestamps', true);
exports.StakeInvestmentInfoSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
exports.StakeInvestmentInfoSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
exports.StakeInvestmentInfoSchema.index({ userId: 1 });
exports.StakeInvestmentInfoSchema.index({ coinId: 1 });
exports.StakeInvestmentInfoSchema.index({ walletId: 1 });
exports.StakeInvestmentInfoSchema.index({ userAddress: 1 });
exports.StakeInvestmentInfoSchema.index({ stakingContractAddress: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1 });
exports.StakeInvestmentInfoSchema.index({ amount: 1 });
exports.StakeInvestmentInfoSchema.index({ startDate: 1 });
exports.StakeInvestmentInfoSchema.index({ endDate: 1 });
exports.StakeInvestmentInfoSchema.index({ isClaimed: 1 });
exports.StakeInvestmentInfoSchema.index({ isWithdrawn: 1 });
exports.StakeInvestmentInfoSchema.index({ createdAt: 1 });
exports.StakeInvestmentInfoSchema.index({ updatedAt: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1, amount: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1, walletId: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1, walletId: 1, userAddress: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1, walletId: 1, userAddress: 1, stakingContractAddress: 1 });
exports.StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1, walletId: 1, userAddress: 1, stakingContractAddress: 1, createdAt: 1 });
//# sourceMappingURL=stake-investment-info.schema.js.map