import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";
import { generateStringId } from "src/utils/utils";

export type DepositBankDetailDocument = HydratedDocument<DepositBankDetail>;

@Schema()
export class DepositBankDetail {
    @Prop({ type: String, default: generateStringId })
    _id: string;

    @Prop({ type: String, default: 'usd', enum: ['usd', 'ngn'] })
    currency: string;

    @Prop({ type: String, default: '' })
    accountHolderName: string;

    @Prop({ type: String, default: '' })
    accountNumber: string;

    @Prop({ type: String, default: '' })
    bank: string;

    @Prop({ type: String, default: '' })
    quote: string;
}

export const DepositBankDetailSchema = SchemaFactory.createForClass(DepositBankDetail);

DepositBankDetailSchema.set('timestamps', true);

DepositBankDetailSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});

DepositBankDetailSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});
