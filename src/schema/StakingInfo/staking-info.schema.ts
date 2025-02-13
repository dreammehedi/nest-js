import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { generateStringId } from "src/utils/utils";
import { HydratedDocument } from "mongoose";
import { Coin } from "../Coin/coin.schema";
import { Network } from "../Network/network.schema";

export type StakingInfoDocument = HydratedDocument<StakingInfo>;

@Schema()
export class StakingInfo {
    @Prop({ type: String, default: generateStringId })
    _id: string;

    @Prop({ type: Number, default: 0 })
    totalInvestments: number;

    @Prop({ type: Number, default: 0 })
    totalStaked: number;

    @Prop({ type: Number, default: 0 })
    totalReward: number;

    @Prop({ type: String, required: true, default: '', transform: (v) => v.toString().trim()?.toLowerCase() })
    stakingContractAddress: string;

    @Prop({ type: String, default: '', required: true, ref: Coin.name })
    coinId: string;

    @Prop({ type: String, default: '', required: true, ref: Network.name })
    networkId: string;
}

export const StakingInfoSchema = SchemaFactory.createForClass(StakingInfo);

StakingInfoSchema.set('timestamps', true);

StakingInfoSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});

StakingInfoSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});

StakingInfoSchema.index({ totalStaked: 1 });
StakingInfoSchema.index({ totalReward: 1 });
StakingInfoSchema.index({ stakingContractAddress: 1 });
StakingInfoSchema.index({ coinId: 1 });
StakingInfoSchema.index({ networkId: 1 });
StakingInfoSchema.index({ createdAt: 1 });
StakingInfoSchema.index({ updatedAt: 1 });
