import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";
import { User } from "src/decorators/user.decorator";
import { generateStringId } from "src/utils/utils";
import { Wallet } from "../Wallet/wallet.schema";
import { Coin } from "../Coin/coin.schema";

export type StakeInvestmentInfoDocument = HydratedDocument<StakeInvestmentInfo>;

@Schema()
export class StakeInvestmentInfo {
    @Prop({ type: String, default: generateStringId })
    _id: string;

    @Prop({ type: String, default: '', ref: User.name })
    userId: string;

    @Prop({ type: String, default: '', ref: Coin.name })
    coinId: string;

    @Prop({ type: String, default: '', ref: Wallet.name })
    walletId: string;

    @Prop({ type: String, default: '' })
    userAddress: string;

    @Prop({ type: String, default: '' })
    stakingContractAddress: string;

    @Prop({ type: Number, default: 0 })
    investmentId: number;

    @Prop({ type: Number, default: 0 })
    planId: number;

    @Prop({ type: Number, default: 0 })
    amount: number;

    @Prop({ type: Date, default: Date.now })
    startDate: Date;

    @Prop({ type: Date, default: Date.now })
    endDate: Date;

    @Prop({ type: Boolean, default: false })
    isClaimed: boolean;

    @Prop({ type: Boolean, default: false })
    isWithdrawn: boolean;

    @Prop({ type: Number, default: 0 })
    dailyReward: number;

    @Prop({ type: Number, default: 0 })
    totalReward: number;
}

export const StakeInvestmentInfoSchema = SchemaFactory.createForClass(StakeInvestmentInfo);

StakeInvestmentInfoSchema.set('timestamps', true);

StakeInvestmentInfoSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});

StakeInvestmentInfoSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});

StakeInvestmentInfoSchema.index({ userId: 1 });
StakeInvestmentInfoSchema.index({ coinId: 1 });
StakeInvestmentInfoSchema.index({ walletId: 1 });
StakeInvestmentInfoSchema.index({ userAddress: 1 });
StakeInvestmentInfoSchema.index({ stakingContractAddress: 1 });
StakeInvestmentInfoSchema.index({ planId: 1 });
StakeInvestmentInfoSchema.index({ amount: 1 });
StakeInvestmentInfoSchema.index({ startDate: 1 });
StakeInvestmentInfoSchema.index({ endDate: 1 });
StakeInvestmentInfoSchema.index({ isClaimed: 1 });
StakeInvestmentInfoSchema.index({ isWithdrawn: 1 });
StakeInvestmentInfoSchema.index({ createdAt: 1 });
StakeInvestmentInfoSchema.index({ updatedAt: 1 });
StakeInvestmentInfoSchema.index({ planId: 1, amount: 1 });
StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1 });
StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1 });
StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1 });
StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1 });
StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1, walletId: 1 });
StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1, walletId: 1, userAddress: 1 });
StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1, walletId: 1, userAddress: 1, stakingContractAddress: 1 });
StakeInvestmentInfoSchema.index({ planId: 1, amount: 1, startDate: 1, endDate: 1, isClaimed: 1, isWithdrawn: 1, userId: 1, coinId: 1, walletId: 1, userAddress: 1, stakingContractAddress: 1, createdAt: 1 });