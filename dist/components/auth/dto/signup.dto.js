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
exports.SignupDTO = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
const NUMBER = /\d/;
const CAPITAL_LETTER = /[A-Z]/;
const SMALL_LETTER = /[a-z]/;
const SPECIAL_CHARACTER = /[ !@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;
const MIN_LENGTH = 8;
class SignupDTO {
}
exports.SignupDTO = SignupDTO;
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], SignupDTO.prototype, "fullname", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], SignupDTO.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.MinLength)(MIN_LENGTH, { message: 'Minimum 8 characters required' }),
    (0, class_validator_1.Matches)(NUMBER, { message: 'Minimum 1 digit required' }),
    (0, class_validator_1.Matches)(CAPITAL_LETTER, {
        message: 'Minimum 1 uppercase character required',
    }),
    (0, class_validator_1.Matches)(SMALL_LETTER, { message: 'Minimum 1 lowercase character required' }),
    (0, class_validator_1.Matches)(SPECIAL_CHARACTER, {
        message: 'Minimum 1 special character required',
    }),
    __metadata("design:type", String)
], SignupDTO.prototype, "password", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], SignupDTO.prototype, "currencyId", void 0);
//# sourceMappingURL=signup.dto.js.map