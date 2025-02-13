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
exports.NetworkSchema = exports.Network = void 0;
const mongoose_1 = require("@nestjs/mongoose");
const network_enum_1 = require("../../enum/network.enum");
const utils_1 = require("../../utils/utils");
let Network = class Network {
};
exports.Network = Network;
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: utils_1.generateStringId }),
    __metadata("design:type", String)
], Network.prototype, "_id", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Network.prototype, "name", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Network.prototype, "symbol", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Network.prototype, "logoUrl", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Network.prototype, "rpcUrl", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Network.prototype, "chainId", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Network.prototype, "nativeCoinAddress", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Network.prototype, "networkName", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: network_enum_1.NETWORKTYPEENUM.EVM, enum: network_enum_1.NETWORKTYPEENUM }),
    __metadata("design:type", String)
], Network.prototype, "networkType", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], Network.prototype, "scanUrl", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], Network.prototype, "isMainnet", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], Network.prototype, "isDeleted", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], Network.prototype, "isActive", void 0);
exports.Network = Network = __decorate([
    (0, mongoose_1.Schema)()
], Network);
exports.NetworkSchema = mongoose_1.SchemaFactory.createForClass(Network);
exports.NetworkSchema.set('toJSON', {
    transform: function (_, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
        delete ret.createdAt;
        delete ret.updatedAt;
        return ret;
    },
});
exports.NetworkSchema.set('toObject', {
    transform: function (_, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
        delete ret.createdAt;
        delete ret.updatedAt;
        return ret;
    },
});
exports.NetworkSchema.set('timestamps', true);
exports.NetworkSchema.index({ name: 1 });
exports.NetworkSchema.index({ symbol: 1 });
exports.NetworkSchema.index({ chainName: 1 });
exports.NetworkSchema.index({ networkName: 1 });
exports.NetworkSchema.index({ networkType: 1 });
exports.NetworkSchema.index({ name: 1, symbol: 1 });
exports.NetworkSchema.index({ chainName: 1, networkName: 1 });
exports.NetworkSchema.index({ chainName: 1, networkName: 1, networkType: 1 });
exports.NetworkSchema.index({
    name: 1,
    symbol: 1,
    chainName: 1,
    networkName: 1,
    networkType: 1,
});
exports.NetworkSchema.index({
    name: 1,
    symbol: 1,
    chainName: 1,
    networkName: 1,
    networkType: 1,
    rpcUrl: 1,
});
exports.NetworkSchema.index({
    name: 1,
    symbol: 1,
    chainName: 1,
    networkName: 1,
    networkType: 1,
    rpcUrl: 1,
    logoUrl: 1,
});
exports.NetworkSchema.index({
    name: 1,
    symbol: 1,
    chainName: 1,
    networkName: 1,
    networkType: 1,
    rpcUrl: 1,
    logoUrl: 1,
    _id: 1,
});
exports.NetworkSchema.index({
    name: 1,
    symbol: 1,
    chainName: 1,
    networkName: 1,
    networkType: 1,
    rpcUrl: 1,
    logoUrl: 1,
    _id: 1,
    createdAt: 1,
});
//# sourceMappingURL=network.schema.js.map