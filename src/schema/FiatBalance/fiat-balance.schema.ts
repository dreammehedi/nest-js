import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";
import { generateStringId } from "src/utils/utils";
import { User } from "../User/user.schema";
import { Currency } from "../Currency/currency.schema";
import { Wallet } from "../Wallet/wallet.schema";

export type FiatBalanceDocument = HydratedDocument<FiatBalance>;

@Schema()
export class FiatBalance {
    @Prop({ type: String, default: generateStringId })
    _id: string;

    @Prop({ type: String, default: '', ref: User.name })
    userId: string;

    @Prop({ type: String, default: '', ref: Wallet.name })
    walletId: string;

    @Prop({ type: String, default: '', ref: Currency.name })
    currencyId: string;

    @Prop({ type: Number, default: 0 })
    balance: number;

    @Prop({ type: Number, default: 0 })
    totalWithdrawnAmount: number;

    @Prop({ type: Number, default: 0 })
    totalWithdrawnAmountLocked: number;
}

export const FiatBalanceSchema = SchemaFactory.createForClass(FiatBalance);

FiatBalanceSchema.set('timestamps', true);

FiatBalanceSchema.set('toJSON', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});

FiatBalanceSchema.set('toObject', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});

FiatBalanceSchema.index({ userId: 1 });
FiatBalanceSchema.index({ currencyId: 1 });
FiatBalanceSchema.index({ balance: 1 });
FiatBalanceSchema.index({ userId: 1, currencyId: 1 });
FiatBalanceSchema.index({ userId: 1, balance: 1 });
