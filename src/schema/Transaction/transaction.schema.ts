import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import {
  TRANSACTIONENUM,
  TRANSACTIONSTATUSENUM,
} from 'src/enum/transaction.enum';
import { generateStringId } from 'src/utils/utils';
import { Currency } from '../Currency/currency.schema';
import { Coin } from '../Coin/coin.schema';

export type TransactionDocument = HydratedDocument<Transaction>;

@Schema()
export class Transaction {
  @Prop({ type: String, default: generateStringId })
  _id: string;

  @Prop({ type: String, default: '' })
  userId: string;

  @Prop({ type: String, default: '' })
  walletId: string;

  @Prop({ type: String, default: '' })
  fromAddress: string;

  @Prop({ type: String, default: '' })
  toAddress: string;

  @Prop({ type: String, default: '' })
  fromCoinId: string;

  @Prop({ type: String, default: '', ref: Coin.name })
  coinId: string;

  @Prop({
    type: String,
    default: TRANSACTIONENUM.DEPOSIT,
    enum: TRANSACTIONENUM,
  })
  type: string;

  @Prop({ type: Number, default: 0 })
  amount: number;

  @Prop({ type: Number, default: 0 })
  fee: number;

  @Prop({ type: Number, default: 0 })
  swapFee: number;

  @Prop({ type: Number, default: 0 })
  balance: number;

  @Prop({ type: Number, default: 0 })
  swappedAmount: number;

  @Prop({ type: Number, default: 0 })
  swappedPrice: number;

  @Prop({ type: String, default: '' })
  trxHash: string;

  @Prop({ type: String, default: '' })
  trxUrl: string;

  @Prop({ type: String, default: '' })
  systemTrxHash: string;

  @Prop({ type: String, default: '' })
  systemTrxUrl: string;

  @Prop({ type: String, default: '' })
  bankName: string;

  @Prop({ type: String, default: '' })
  accountNumber: string;

  @Prop({ type: String, default: '' })
  accountName: string;

  @Prop({
    type: String,
    enum: TRANSACTIONSTATUSENUM,
    default: TRANSACTIONSTATUSENUM.COMPLETED,
  })
  status: string;

  @Prop({ type: String, default: '', ref: Currency.name })
  currencyId: string;

  @Prop({ type: String, default: '' })
  country: string;

  @Prop({ type: String, default: '' })
  proofOfPayment: string;

  @Prop({ type: String, default: '' })
  paymentMethod: string;
}

export const TransactionSchema = SchemaFactory.createForClass(Transaction);

TransactionSchema.set('toJSON', {
  transform: function (doc, ret) {
    ret.id = ret._id;
    delete ret.__v;
    delete ret._id;
  },
});

TransactionSchema.set('toObject', {
  transform: function (doc, ret) {
    ret.id = ret._id;
    delete ret.__v;
    delete ret._id;
  },
});

TransactionSchema.set('timestamps', true);
