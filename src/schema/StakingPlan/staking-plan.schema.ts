import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";
import { generateStringId } from "src/utils/utils";
import { Coin } from "../Coin/coin.schema";
import { Network } from "../Network/network.schema";

export type StakingPlanDocument = HydratedDocument<StakingPlan>;

@Schema()
export class StakingPlan {
    @Prop({ type: String, default: generateStringId })
    _id: string;

    @Prop({ type: Number, default: 0 })
    planId: number;

    @Prop({ type: Number, required: true, default: 0 })
    duration: number;

    @Prop({ type: Number, required: true, default: 0 })
    interestRate: number;

    @Prop({ type: Boolean, required: true, default: false })
    isActive: boolean;

    @Prop({ type: String, required: true, default: '', transform: (v) => v.toString().trim()?.toLowerCase() })
    stakingContractAddress: string;

    @Prop({ type: String, default: '', required: true, ref: Coin.name })
    coinId: string;

    @Prop({ type: String, default: '', required: true, ref: Network.name })
    networkId: string;
}

export const StakingPlanSchema = SchemaFactory.createForClass(StakingPlan);

StakingPlanSchema.set('timestamps', true);

StakingPlanSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});

StakingPlanSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});

StakingPlanSchema.index({ isActive: 1 });
StakingPlanSchema.index({ duration: 1 });
StakingPlanSchema.index({ interestRate: 1 });
