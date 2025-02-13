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
exports.DonationOrganizationSchema = exports.DonationOrganization = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const utils_1 = require("../../utils/utils");
let DonationOrganization = class DonationOrganization {
};
exports.DonationOrganization = DonationOrganization;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], DonationOrganization.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], DonationOrganization.prototype, "name", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], DonationOrganization.prototype, "walletAddress", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: true }),
    __metadata("design:type", Boolean)
], DonationOrganization.prototype, "isActive", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], DonationOrganization.prototype, "isDeleted", void 0);
exports.DonationOrganization = DonationOrganization = __decorate([
    (0, mongoose_1.Schema)()
], DonationOrganization);
exports.DonationOrganizationSchema = mongoose_1.SchemaFactory.createForClass(DonationOrganization);
exports.DonationOrganizationSchema.set('timestamps', true);
exports.DonationOrganizationSchema.set('toJSON', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});
exports.DonationOrganizationSchema.set('toObject', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});
exports.DonationOrganizationSchema.index({ name: 1 });
exports.DonationOrganizationSchema.index({ walletAddress: 1 });
//# sourceMappingURL=donation-organization.schema.js.map