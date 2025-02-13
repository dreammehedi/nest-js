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
exports.UpdateTransactionDTO = exports.TransactionDTO = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
const transaction_enum_1 = require("../../../enum/transaction.enum");
class TransactionDTO {
}
exports.TransactionDTO = TransactionDTO;
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], TransactionDTO.prototype, "limit", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], TransactionDTO.prototype, "offset", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false, enum: transaction_enum_1.TRANSACTIONENUM }),
    __metadata("design:type", String)
], TransactionDTO.prototype, "type", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false, enum: transaction_enum_1.TRANSACTIONSTATUSENUM }),
    __metadata("design:type", String)
], TransactionDTO.prototype, "status", void 0);
class UpdateTransactionDTO {
}
exports.UpdateTransactionDTO = UpdateTransactionDTO;
__decorate([
    (0, swagger_1.ApiProperty)({ required: true }),
    __metadata("design:type", String)
], UpdateTransactionDTO.prototype, "transactionId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: true, enum: transaction_enum_1.TRANSACTIONSTATUSENUM }),
    (0, class_validator_1.IsEnum)(transaction_enum_1.TRANSACTIONSTATUSENUM),
    __metadata("design:type", String)
], UpdateTransactionDTO.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ required: false }),
    __metadata("design:type", String)
], UpdateTransactionDTO.prototype, "trxUrl", void 0);
//# sourceMappingURL=transaction.dto.js.map