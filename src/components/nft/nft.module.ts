import { Module } from '@nestjs/common';
import { NftController } from './nft.controller';
import { NftService } from './nft.service';
import { MongooseModule } from '@nestjs/mongoose';
import { NFT, NFTSchema } from 'src/schema/Nft/nft.schema';
import { Wallet, WalletSchema } from 'src/schema/Wallet/wallet.schema';
import { Network, NetworkSchema } from 'src/schema/Network/network.schema';
import { User, UserSchema } from 'src/schema/User/user.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: NFT.name, schema: NFTSchema },
      { name: Network.name, schema: NetworkSchema },
      { name: Wallet.name, schema: WalletSchema },
      { name: User.name, schema: UserSchema },
    ]),
  ],
  controllers: [NftController],
  providers: [NftService],
  exports: [NftService],
})
export class NftModule {}
