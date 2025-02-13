import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { generateStringId } from 'src/utils/utils';

export type NFTDocument = HydratedDocument<NFT>;

@Schema()
export class NFT {
  @Prop({ type: String, default: generateStringId })
  _id: string;

  @Prop({ type: String, default: '' })
  name: string;

  @Prop({ type: String, default: '' })
  symbol: string;

  @Prop({ type: String, default: '' })
  tokenId: string;

  @Prop({ type: String, default: '' })
  walletId: string;

  @Prop({ type: String, default: '' })
  userId: string;

  @Prop({ type: String, default: '' })
  owner: string;

  @Prop({ type: String, enum: ['ERC721', 'ERC1155'], default: 'ERC721' })
  type: string;

  @Prop({ type: String, default: '' })
  networkId: string;

  @Prop({ type: String, default: '' })
  tokenUri: string;

  @Prop({ type: String, default: '' })
  contractAddress: string;

  @Prop({ type: Number, default: 1 })
  amount: number;

  @Prop({ type: String, default: '' })
  imageUrl: string;
}

export const NFTSchema = SchemaFactory.createForClass(NFT);

NFTSchema.set('timestamps', true);

NFTSchema.set('toJSON', {
  transform: function (_, ret) {
    ret.id = ret._id;
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

NFTSchema.set('toObject', {
  transform: function (_, ret) {
    ret.id = ret._id;
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

NFTSchema.index({ name: 1 });
NFTSchema.index({ symbol: 1 });
NFTSchema.index({ tokenId: 1 });
NFTSchema.index({ owner: 1 });
NFTSchema.index({ type: 1 });
NFTSchema.index({ networkId: 1 });
NFTSchema.index({ contractAddress: 1 });
NFTSchema.index({ amount: 1 });
NFTSchema.index({ createdAt: 1 });
NFTSchema.index({ updatedAt: 1 });
NFTSchema.index({ name: 1, symbol: 1 });
NFTSchema.index({ tokenId: 1, owner: 1 });
NFTSchema.index({ networkId: 1, contractAddress: 1 });
NFTSchema.index({ networkId: 1, contractAddress: 1, tokenId: 1 });
NFTSchema.index({ networkId: 1, contractAddress: 1, tokenId: 1, owner: 1 });
NFTSchema.index({
  networkId: 1,
  contractAddress: 1,
  tokenId: 1,
  owner: 1,
  amount: 1,
});
NFTSchema.index({ networkId: 1, contractAddress: 1, tokenId: 1, amount: 1 });
NFTSchema.index({
  networkId: 1,
  contractAddress: 1,
  tokenId: 1,
  amount: 1,
  owner: 1,
});
NFTSchema.index({
  networkId: 1,
  contractAddress: 1,
  tokenId: 1,
  amount: 1,
  owner: 1,
  type: 1,
});
NFTSchema.index({
  networkId: 1,
  contractAddress: 1,
  tokenId: 1,
  amount: 1,
  owner: 1,
  type: 1,
  symbol: 1,
});
NFTSchema.index({
  networkId: 1,
  contractAddress: 1,
  tokenId: 1,
  amount: 1,
  owner: 1,
  type: 1,
  symbol: 1,
  name: 1,
});
NFTSchema.index({
  networkId: 1,
  contractAddress: 1,
  tokenId: 1,
  amount: 1,
  owner: 1,
  type: 1,
  symbol: 1,
  name: 1,
  createdAt: 1,
});
NFTSchema.index({
  networkId: 1,
  contractAddress: 1,
  tokenId: 1,
  amount: 1,
  owner: 1,
  type: 1,
  symbol: 1,
  name: 1,
  createdAt: 1,
  updatedAt: 1,
});
NFTSchema.index({
  networkId: 1,
  contractAddress: 1,
  tokenId: 1,
  amount: 1,
  owner: 1,
  type: 1,
  symbol: 1,
  name: 1,
  createdAt: 1,
  updatedAt: 1,
  isDeleted: 1,
});
