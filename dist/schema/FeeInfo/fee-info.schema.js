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
exports.FeeInfoSchema = exports.FeeInfo = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const utils_1 = require("../../utils/utils");
let FeeInfo = class FeeInfo {
};
exports.FeeInfo = FeeInfo;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], FeeInfo.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], FeeInfo.prototype, "feeName", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], FeeInfo.prototype, "feePercentage", void 0);
exports.FeeInfo = FeeInfo = __decorate([
    (0, mongoose_1.Schema)()
], FeeInfo);
exports.FeeInfoSchema = mongoose_1.SchemaFactory.createForClass(FeeInfo);
exports.FeeInfoSchema.set('toJSON', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret.__v;
        delete ret._id;
    },
});
exports.FeeInfoSchema.set('toObject', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret.__v;
        delete ret._id;
    },
});
exports.FeeInfoSchema.set('timestamps', true);
exports.FeeInfoSchema.index({ feeName: 1, feePercentage: 1 });
//# sourceMappingURL=fee-info.schema.js.map