import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { Banner, BannerSchema } from 'src/schema/banner/banner.schema';
import { Currency, CurrencySchema } from 'src/schema/Currency/currency.schema';
import { NFT, NFTSchema } from 'src/schema/Nft/nft.schema';
import { Otp, OtpSchema } from 'src/schema/OTP/otp.schema';
import { User, UserSchema } from 'src/schema/User/user.schema';
import { NftModule } from '../nft/nft.module';
import { UtilsService } from '../utils/utils.service';
import { WalletModule } from '../wallet/wallet.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';

@Module({})
export class AuthModule {
  static forRoot(): any {
    return {
      imports: [
        MongooseModule.forFeature([
          { name: User.name, schema: UserSchema },
          { name: Otp.name, schema: OtpSchema },
          { name: Currency.name, schema: CurrencySchema },
          { name: NFT.name, schema: NFTSchema },
          { name: Banner.name, schema: BannerSchema },
        ]),
        JwtModule.register({
          secret: process.env.JWT_SECRET,
          signOptions: { expiresIn: '99999999999s' },
        }),
        WalletModule,
        NftModule,
      ],
      controllers: [AuthController],
      providers: [AuthService, JwtStrategy, UtilsService],
      module: AuthModule,
    };
  }
}
