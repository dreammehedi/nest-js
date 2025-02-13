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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CoinsController = void 0;
const common_1 = require("@nestjs/common");
const swagger_1 = require("@nestjs/swagger");
const coins_service_1 = require("./coins.service");
let CoinsController = class CoinsController {
    constructor(_coinsService) {
        this._coinsService = _coinsService;
    }
    async getCurrencies(limit = 10, offset = 0, name = null) {
        return await this._coinsService.getCurrencies(limit, offset, name);
    }
    async getCoins(limit = 10, offset = 0, coinId = null, networkId = null, amount = 1) {
        return await this._coinsService.getCoins(limit, offset, coinId, networkId, amount);
    }
    async getCoinsPrice(limit = 10, offset = 0, coinNameSearch = null, networkId = null, currencyId = null) {
        return await this._coinsService.getCoinsPrice(limit, offset, coinNameSearch, networkId, currencyId);
    }
    async getNetworks() {
        return await this._coinsService.getNetworks();
    }
};
exports.CoinsController = CoinsController;
__decorate([
    (0, swagger_1.ApiQuery)({ name: 'limit', required: false, type: Number, example: 10 }),
    (0, swagger_1.ApiQuery)({ name: 'offset', required: false, type: Number, example: 0 }),
    (0, swagger_1.ApiQuery)({ name: 'name', required: false, type: String }),
    (0, common_1.Get)('getCurrencies'),
    __param(0, (0, common_1.Query)('limit')),
    __param(1, (0, common_1.Query)('offset')),
    __param(2, (0, common_1.Query)('name')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, String]),
    __metadata("design:returntype", Promise)
], CoinsController.prototype, "getCurrencies", null);
__decorate([
    (0, swagger_1.ApiQuery)({ name: 'limit', required: false, type: Number, example: 10 }),
    (0, swagger_1.ApiQuery)({ name: 'offset', required: false, type: Number, example: 0 }),
    (0, swagger_1.ApiQuery)({ name: 'coinId', required: false, type: String }),
    (0, swagger_1.ApiQuery)({ name: 'networkId', required: false, type: String }),
    (0, swagger_1.ApiQuery)({ name: 'amount', required: false, type: Number, example: 1 }),
    (0, common_1.Get)('getCoins'),
    __param(0, (0, common_1.Query)('limit')),
    __param(1, (0, common_1.Query)('offset')),
    __param(2, (0, common_1.Query)('coinId')),
    __param(3, (0, common_1.Query)('networkId')),
    __param(4, (0, common_1.Query)('amount')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, String, String, Object]),
    __metadata("design:returntype", Promise)
], CoinsController.prototype, "getCoins", null);
__decorate([
    (0, swagger_1.ApiQuery)({ name: 'limit', required: false, type: Number, example: 10 }),
    (0, swagger_1.ApiQuery)({ name: 'offset', required: false, type: Number, example: 0 }),
    (0, swagger_1.ApiQuery)({ name: 'coinNameSearch', required: false, type: String }),
    (0, swagger_1.ApiQuery)({ name: 'networkId', required: false, type: String }),
    (0, swagger_1.ApiQuery)({ name: 'currencyId', required: false, type: String }),
    (0, common_1.Get)('getCoinsPrice'),
    __param(0, (0, common_1.Query)('limit')),
    __param(1, (0, common_1.Query)('offset')),
    __param(2, (0, common_1.Query)('coinNameSearch')),
    __param(3, (0, common_1.Query)('networkId')),
    __param(4, (0, common_1.Query)('currencyId')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, String, String, String]),
    __metadata("design:returntype", Promise)
], CoinsController.prototype, "getCoinsPrice", null);
__decorate([
    (0, common_1.Get)('getNetworks'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], CoinsController.prototype, "getNetworks", null);
exports.CoinsController = CoinsController = __decorate([
    (0, swagger_1.ApiTags)('Coins'),
    (0, common_1.Controller)('coins'),
    __metadata("design:paramtypes", [coins_service_1.CoinsService])
], CoinsController);
//# sourceMappingURL=coins.controller.js.map