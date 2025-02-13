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
exports.StakingPlanSchema = exports.StakingPlan = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const utils_1 = require("../../utils/utils");
const coin_schema_1 = require("../Coin/coin.schema");
const network_schema_1 = require("../Network/network.schema");
let StakingPlan = class StakingPlan {
};
exports.StakingPlan = StakingPlan;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], StakingPlan.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], StakingPlan.prototype, "planId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, required: true, default: 0 }),
    __metadata("design:type", Number)
], StakingPlan.prototype, "duration", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, required: true, default: 0 }),
    __metadata("design:type", Number)
], StakingPlan.prototype, "interestRate", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, required: true, default: false }),
    __metadata("design:type", Boolean)
], StakingPlan.prototype, "isActive", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, required: true, default: '', transform: (v) => v.toString().trim()?.toLowerCase() }),
    __metadata("design:type", String)
], StakingPlan.prototype, "stakingContractAddress", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', required: true, ref: coin_schema_1.Coin.name }),
    __metadata("design:type", String)
], StakingPlan.prototype, "coinId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '', required: true, ref: network_schema_1.Network.name }),
    __metadata("design:type", String)
], StakingPlan.prototype, "networkId", void 0);
exports.StakingPlan = StakingPlan = __decorate([
    (0, mongoose_1.Schema)()
], StakingPlan);
exports.StakingPlanSchema = mongoose_1.SchemaFactory.createForClass(StakingPlan);
exports.StakingPlanSchema.set('timestamps', true);
exports.StakingPlanSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
exports.StakingPlanSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
exports.StakingPlanSchema.index({ isActive: 1 });
exports.StakingPlanSchema.index({ duration: 1 });
exports.StakingPlanSchema.index({ interestRate: 1 });
//# sourceMappingURL=staking-plan.schema.js.map