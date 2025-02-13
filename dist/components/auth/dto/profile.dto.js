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
exports.UpdateProfileDTO = void 0;
const swagger_1 = require("@nestjs/swagger");
class UpdateProfileDTO {
}
exports.UpdateProfileDTO = UpdateProfileDTO;
__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    __metadata("design:type", String)
], UpdateProfileDTO.prototype, "image", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    __metadata("design:type", String)
], UpdateProfileDTO.prototype, "fullname", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    __metadata("design:type", String)
], UpdateProfileDTO.prototype, "phone", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    __metadata("design:type", String)
], UpdateProfileDTO.prototype, "bankName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    __metadata("design:type", String)
], UpdateProfileDTO.prototype, "accountNumber", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    __metadata("design:type", String)
], UpdateProfileDTO.prototype, "accountName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false, default: false }),
    __metadata("design:type", Boolean)
], UpdateProfileDTO.prototype, "isAuthEnabled", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false, default: false }),
    __metadata("design:type", Boolean)
], UpdateProfileDTO.prototype, "isBiometricEnabled", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    __metadata("design:type", String)
], UpdateProfileDTO.prototype, "currencyId", void 0);
//# sourceMappingURL=profile.dto.js.map