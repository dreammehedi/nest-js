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
exports.OtpSchema = exports.Otp = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const otp_enum_1 = require("../../enum/otp.enum");
const utils_1 = require("../../utils/utils");
let Otp = class Otp {
};
exports.Otp = Otp;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], Otp.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({
        type: String,
        default: otp_enum_1.OTPTYPEENUM.VERIFY,
        enum: otp_enum_1.OTPTYPEENUM,
    }),
    __metadata("design:type", String)
], Otp.prototype, "otpType", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: 0 }),
    __metadata("design:type", String)
], Otp.prototype, "otp", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Otp.prototype, "userId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Date, default: () => new Date(Date.now() + 120000) }),
    __metadata("design:type", Date)
], Otp.prototype, "expiryTime", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], Otp.prototype, "isUsed", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], Otp.prototype, "isChangeEmail", void 0);
exports.Otp = Otp = __decorate([
    (0, mongoose_1.Schema)()
], Otp);
exports.OtpSchema = mongoose_1.SchemaFactory.createForClass(Otp);
exports.OtpSchema.set('timestamps', true);
exports.OtpSchema.set('toJSON', {
    transform: function (_, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
        return ret;
    },
});
exports.OtpSchema.set('toObject', {
    transform: function (_, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
        return ret;
    },
});
exports.OtpSchema.index({ createdAt: 1 }, { expireAfterSeconds: 120 });
exports.OtpSchema.index({ userId: 1, otp: 1 });
exports.OtpSchema.index({ userId: 1, expiryTime: 1 });
exports.OtpSchema.index({ userId: 1, createdAt: 1 });
exports.OtpSchema.index({ userId: 1, otp: 1, expiryTime: 1 });
exports.OtpSchema.index({ userId: 1, otp: 1, createdAt: 1 });
exports.OtpSchema.index({ userId: 1, otp: 1, expiryTime: 1, createdAt: 1 });
exports.OtpSchema.index({
    userId: 1,
    otp: 1,
    expiryTime: 1,
    createdAt: 1,
    updatedAt: 1,
});
exports.OtpSchema.index({
    userId: 1,
    otp: 1,
    expiryTime: 1,
    createdAt: 1,
    updatedAt: 1,
    _id: 1,
});
//# sourceMappingURL=otp.schema.js.map