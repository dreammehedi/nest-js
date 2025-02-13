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
exports.CoinPriceSchema = exports.CoinPrice = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const utils_1 = require("../../utils/utils");
let CoinPrice = class CoinPrice {
};
exports.CoinPrice = CoinPrice;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], CoinPrice.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], CoinPrice.prototype, "coinId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], CoinPrice.prototype, "networkId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], CoinPrice.prototype, "currencyId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], CoinPrice.prototype, "name", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], CoinPrice.prototype, "priceMarket", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], CoinPrice.prototype, "priceFormer", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], CoinPrice.prototype, "price", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], CoinPrice.prototype, "priceChange", void 0);
exports.CoinPrice = CoinPrice = __decorate([
    (0, mongoose_1.Schema)()
], CoinPrice);
exports.CoinPriceSchema = mongoose_1.SchemaFactory.createForClass(CoinPrice);
exports.CoinPriceSchema.set('toJSON', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret.__v;
        delete ret._id;
    },
});
exports.CoinPriceSchema.set('toObject', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret.__v;
        delete ret._id;
    },
});
exports.CoinPriceSchema.set('timestamps', true);
exports.CoinPriceSchema.index({ coinId: 1, currencyId: 1 });
exports.CoinPriceSchema.index({ coinId: 1, currencyId: 1, priceMarket: 1 });
exports.CoinPriceSchema.index({ coinId: 1, currencyId: 1, priceFormer: 1 });
exports.CoinPriceSchema.index({ coinId: 1, currencyId: 1, price: 1 });
exports.CoinPriceSchema.index({ coinId: 1, currencyId: 1, priceChange: 1 });
exports.CoinPriceSchema.index({ coinId: 1, currencyId: 1, createdAt: 1 });
exports.CoinPriceSchema.index({ coinId: 1, currencyId: 1, updatedAt: 1 });
//# sourceMappingURL=coin-price.schema.js.map