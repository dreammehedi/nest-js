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
exports.UserStakeInfoSchema = exports.UserStakeInfo = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const user_decorator_1 = require("../../decorators/user.decorator");
const utils_1 = require("../../utils/utils");
const coin_schema_1 = require("../Coin/coin.schema");
let UserStakeInfo = class UserStakeInfo {
};
exports.UserStakeInfo = UserStakeInfo;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], UserStakeInfo.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: user_decorator_1.User.name }),
    __metadata("design:type", String)
], UserStakeInfo.prototype, "userId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', ref: coin_schema_1.Coin.name }),
    __metadata("design:type", String)
], UserStakeInfo.prototype, "coinId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], UserStakeInfo.prototype, "totalInvestments", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], UserStakeInfo.prototype, "totalStaked", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], UserStakeInfo.prototype, "totalRewards", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: (Array), default: [] }),
    __metadata("design:type", Array)
], UserStakeInfo.prototype, "investmentIds", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, required: true, default: '', transform: (v) => v.toString().trim()?.toLowerCase() }),
    __metadata("design:type", String)
], UserStakeInfo.prototype, "stakingContractAddress", void 0);
exports.UserStakeInfo = UserStakeInfo = __decorate([
    (0, mongoose_1.Schema)()
], UserStakeInfo);
exports.UserStakeInfoSchema = mongoose_1.SchemaFactory.createForClass(UserStakeInfo);
exports.UserStakeInfoSchema.set('timestamps', true);
exports.UserStakeInfoSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
exports.UserStakeInfoSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
exports.UserStakeInfoSchema.index({ userId: 1 });
exports.UserStakeInfoSchema.index({ coinId: 1 });
exports.UserStakeInfoSchema.index({ totalStaked: 1 });
exports.UserStakeInfoSchema.index({ totalRewards: 1 });
exports.UserStakeInfoSchema.index({ stakingContractAddress: 1 });
exports.UserStakeInfoSchema.index({ createdAt: 1 });
exports.UserStakeInfoSchema.index({ updatedAt: 1 });
//# sourceMappingURL=user-stake-info.schema.js.map