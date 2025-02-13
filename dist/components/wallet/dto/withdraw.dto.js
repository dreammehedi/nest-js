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
exports.WithdrawFiatDTO = exports.SwapDTO = exports.WithdrawDTO = void 0;
const swagger_1 = require("@nestjs/swagger");
const coinNetwork_dto_1 = require("./coinNetwork.dto");
const class_validator_1 = require("class-validator");
class WithdrawDTO extends coinNetwork_dto_1.CoinNetworkDTO {
}
exports.WithdrawDTO = WithdrawDTO;
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], WithdrawDTO.prototype, "address", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsPositive)(),
    __metadata("design:type", Number)
], WithdrawDTO.prototype, "amount", void 0);
class SwapDTO extends coinNetwork_dto_1.CoinNetworkDTO {
}
exports.SwapDTO = SwapDTO;
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsPositive)(),
    __metadata("design:type", Number)
], SwapDTO.prototype, "amount", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], SwapDTO.prototype, "currencyId", void 0);
class WithdrawFiatDTO {
}
exports.WithdrawFiatDTO = WithdrawFiatDTO;
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsPositive)(),
    __metadata("design:type", Number)
], WithdrawFiatDTO.prototype, "amount", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], WithdrawFiatDTO.prototype, "currencyId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    __metadata("design:type", String)
], WithdrawFiatDTO.prototype, "bankName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    __metadata("design:type", String)
], WithdrawFiatDTO.prototype, "accountNumber", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    __metadata("design:type", String)
], WithdrawFiatDTO.prototype, "accountName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    __metadata("design:type", String)
], WithdrawFiatDTO.prototype, "country", void 0);
//# sourceMappingURL=withdraw.dto.js.map