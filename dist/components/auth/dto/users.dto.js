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
exports.UpdateUserRoleDTO = exports.UpdateUserActiveDTO = exports.GetUsersDTO = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
const user_enum_1 = require("../../../enum/user.enum");
class GetUsersDTO {
}
exports.GetUsersDTO = GetUsersDTO;
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], GetUsersDTO.prototype, "limit", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], GetUsersDTO.prototype, "offset", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false, type: Boolean }),
    __metadata("design:type", Object)
], GetUsersDTO.prototype, "filterOnlyAdmins", void 0);
class UpdateUserActiveDTO {
}
exports.UpdateUserActiveDTO = UpdateUserActiveDTO;
__decorate([
    (0, swagger_1.ApiProperty)({ required: true, type: String }),
    __metadata("design:type", String)
], UpdateUserActiveDTO.prototype, "userId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: true, type: Boolean }),
    __metadata("design:type", Boolean)
], UpdateUserActiveDTO.prototype, "isActive", void 0);
class UpdateUserRoleDTO {
}
exports.UpdateUserRoleDTO = UpdateUserRoleDTO;
__decorate([
    (0, swagger_1.ApiProperty)({ required: true, type: String }),
    __metadata("design:type", String)
], UpdateUserRoleDTO.prototype, "userId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: true, enum: user_enum_1.UserRoleENUM }),
    (0, class_validator_1.IsEnum)(user_enum_1.UserRoleENUM),
    __metadata("design:type", String)
], UpdateUserRoleDTO.prototype, "role", void 0);
//# sourceMappingURL=users.dto.js.map