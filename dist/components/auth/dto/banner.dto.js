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
exports.GetBannerDTO = exports.UpdateBannerDTO = exports.AddBannerDTO = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
class AddBannerDTO {
}
exports.AddBannerDTO = AddBannerDTO;
__decorate([
    (0, swagger_1.ApiProperty)({ required: true, type: String }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], AddBannerDTO.prototype, "mediaUrl", void 0);
class UpdateBannerDTO {
}
exports.UpdateBannerDTO = UpdateBannerDTO;
__decorate([
    (0, swagger_1.ApiProperty)({ required: true, type: String }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UpdateBannerDTO.prototype, "bannerId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false, type: String }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UpdateBannerDTO.prototype, "mediaUrl", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false, type: Boolean }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsBoolean)(),
    __metadata("design:type", Boolean)
], UpdateBannerDTO.prototype, "isActive", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false, type: Boolean }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsBoolean)(),
    __metadata("design:type", Boolean)
], UpdateBannerDTO.prototype, "isDeleted", void 0);
class GetBannerDTO {
}
exports.GetBannerDTO = GetBannerDTO;
__decorate([
    (0, swagger_1.ApiProperty)({ type: Boolean, required: false, default: null }),
    __metadata("design:type", Object)
], GetBannerDTO.prototype, "isDeleted", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ type: Boolean, required: false, default: null }),
    __metadata("design:type", Object)
], GetBannerDTO.prototype, "isActive", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ type: Number, required: false, default: 10 }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Number)
], GetBannerDTO.prototype, "limit", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ type: Number, required: false, default: 0 }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Number)
], GetBannerDTO.prototype, "offset", void 0);
//# sourceMappingURL=banner.dto.js.map