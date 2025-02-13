"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var AuthModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthModule = void 0;
const common_1 = require("@nestjs/common");
const auth_controller_1 = require("./auth.controller");
const auth_service_1 = require("./auth.service");
const mongoose_1 = require("@nestjs/mongoose");
const user_schema_1 = require("../../schema/User/user.schema");
const otp_schema_1 = require("../../schema/OTP/otp.schema");
const jwt_1 = require("@nestjs/jwt");
const jwt_strategy_1 = require("./jwt.strategy");
const utils_service_1 = require("../utils/utils.service");
const wallet_module_1 = require("../wallet/wallet.module");
const currency_schema_1 = require("../../schema/Currency/currency.schema");
const nft_schema_1 = require("../../schema/Nft/nft.schema");
const nft_module_1 = require("../nft/nft.module");
const banner_schema_1 = require("../../schema/banner/banner.schema");
let AuthModule = AuthModule_1 = class AuthModule {
    static forRoot() {
        return {
            imports: [
                mongoose_1.MongooseModule.forFeature([
                    { name: user_schema_1.User.name, schema: user_schema_1.UserSchema },
                    { name: otp_schema_1.Otp.name, schema: otp_schema_1.OtpSchema },
                    { name: currency_schema_1.Currency.name, schema: currency_schema_1.CurrencySchema },
                    { name: nft_schema_1.NFT.name, schema: nft_schema_1.NFTSchema },
                    { name: banner_schema_1.Banner.name, schema: banner_schema_1.BannerSchema },
                ]),
                jwt_1.JwtModule.register({
                    secret: process.env.JWT_SECRET,
                    signOptions: { expiresIn: '99999999999s' },
                }),
                wallet_module_1.WalletModule,
                nft_module_1.NftModule,
            ],
            controllers: [auth_controller_1.AuthController],
            providers: [auth_service_1.AuthService, jwt_strategy_1.JwtStrategy, utils_service_1.UtilsService],
            module: AuthModule_1,
        };
    }
};
exports.AuthModule = AuthModule;
exports.AuthModule = AuthModule = AuthModule_1 = __decorate([
    (0, common_1.Module)({})
], AuthModule);
//# sourceMappingURL=auth.module.js.map