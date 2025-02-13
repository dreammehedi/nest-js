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
exports.StakingInfoSchema = exports.StakingInfo = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const utils_1 = require("../../utils/utils");
const coin_schema_1 = require("../Coin/coin.schema");
const network_schema_1 = require("../Network/network.schema");
let StakingInfo = class StakingInfo {
};
exports.StakingInfo = StakingInfo;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], StakingInfo.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], StakingInfo.prototype, "totalInvestments", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], StakingInfo.prototype, "totalStaked", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], StakingInfo.prototype, "totalReward", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, required: true, default: '', transform: (v) => v.toString().trim()?.toLowerCase() }),
    __metadata("design:type", String)
], StakingInfo.prototype, "stakingContractAddress", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', required: true, ref: coin_schema_1.Coin.name }),
    __metadata("design:type", String)
], StakingInfo.prototype, "coinId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', required: true, ref: network_schema_1.Network.name }),
    __metadata("design:type", String)
], StakingInfo.prototype, "networkId", void 0);
exports.StakingInfo = StakingInfo = __decorate([
    (0, mongoose_1.Schema)()
], StakingInfo);
exports.StakingInfoSchema = mongoose_1.SchemaFactory.createForClass(StakingInfo);
exports.StakingInfoSchema.set('timestamps', true);
exports.StakingInfoSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
exports.StakingInfoSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
exports.StakingInfoSchema.index({ totalStaked: 1 });
exports.StakingInfoSchema.index({ totalReward: 1 });
exports.StakingInfoSchema.index({ stakingContractAddress: 1 });
exports.StakingInfoSchema.index({ coinId: 1 });
exports.StakingInfoSchema.index({ networkId: 1 });
exports.StakingInfoSchema.index({ createdAt: 1 });
exports.StakingInfoSchema.index({ updatedAt: 1 });
//# sourceMappingURL=staking-info.schema.js.map