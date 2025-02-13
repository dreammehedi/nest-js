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
exports.ChangeEmailDTO = exports.ChangePasswordDTO = exports.PasswordDTO = void 0;
const swagger_1 = require("@nestjs/swagger");
class PasswordDTO {
}
exports.PasswordDTO = PasswordDTO;
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], PasswordDTO.prototype, "password", void 0);
class ChangePasswordDTO {
}
exports.ChangePasswordDTO = ChangePasswordDTO;
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], ChangePasswordDTO.prototype, "oldPassword", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], ChangePasswordDTO.prototype, "password", void 0);
class ChangeEmailDTO {
}
exports.ChangeEmailDTO = ChangeEmailDTO;
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], ChangeEmailDTO.prototype, "oldEmail", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], ChangeEmailDTO.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], ChangeEmailDTO.prototype, "password", void 0);
//# sourceMappingURL=password.dto.js.map