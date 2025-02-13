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
exports.DepositBankDetailSchema = exports.DepositBankDetail = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const utils_1 = require("../../utils/utils");
let DepositBankDetail = class DepositBankDetail {
};
exports.DepositBankDetail = DepositBankDetail;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], DepositBankDetail.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: 'usd', enum: ['usd', 'ngn'] }),
    __metadata("design:type", String)
], DepositBankDetail.prototype, "currency", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], DepositBankDetail.prototype, "accountHolderName", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], DepositBankDetail.prototype, "accountNumber", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], DepositBankDetail.prototype, "bank", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], DepositBankDetail.prototype, "quote", void 0);
exports.DepositBankDetail = DepositBankDetail = __decorate([
    (0, mongoose_1.Schema)()
], DepositBankDetail);
exports.DepositBankDetailSchema = mongoose_1.SchemaFactory.createForClass(DepositBankDetail);
exports.DepositBankDetailSchema.set('timestamps', true);
exports.DepositBankDetailSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
exports.DepositBankDetailSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
//# sourceMappingURL=deposit-bank-detail.schema.js.map