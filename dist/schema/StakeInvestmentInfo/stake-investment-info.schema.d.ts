/// <reference types="mongoose/types/aggregate" />
/// <reference types="mongoose/types/callback" />
/// <reference types="mongoose/types/collection" />
/// <reference types="mongoose/types/connection" />
/// <reference types="mongoose/types/cursor" />
/// <reference types="mongoose/types/document" />
/// <reference types="mongoose/types/error" />
/// <reference types="mongoose/types/expressions" />
/// <reference types="mongoose/types/helpers" />
/// <reference types="mongoose/types/middlewares" />
/// <reference types="mongoose/types/indexes" />
/// <reference types="mongoose/types/models" />
/// <reference types="mongoose/types/mongooseoptions" />
/// <reference types="mongoose/types/pipelinestage" />
/// <reference types="mongoose/types/populate" />
/// <reference types="mongoose/types/query" />
/// <reference types="mongoose/types/schemaoptions" />
/// <reference types="mongoose/types/schematypes" />
/// <reference types="mongoose/types/session" />
/// <reference types="mongoose/types/types" />
/// <reference types="mongoose/types/utility" />
/// <reference types="mongoose/types/validation" />
/// <reference types="mongoose/types/virtuals" />
/// <reference types="mongoose/types/inferschematype" />
import { HydratedDocument } from "mongoose";
export type StakeInvestmentInfoDocument = HydratedDocument<StakeInvestmentInfo>;
export declare class StakeInvestmentInfo {
    _id: string;
    userId: string;
    coinId: string;
    walletId: string;
    userAddress: string;
    stakingContractAddress: string;
    investmentId: number;
    planId: number;
    amount: number;
    startDate: Date;
    endDate: Date;
    isClaimed: boolean;
    isWithdrawn: boolean;
    dailyReward: number;
    totalReward: number;
}
export declare const StakeInvestmentInfoSchema: import("mongoose").Schema<StakeInvestmentInfo, import("mongoose").Model<StakeInvestmentInfo, any, any, any, import("mongoose").Document<unknown, any, StakeInvestmentInfo> & StakeInvestmentInfo & Required<{
    _id: string;
}>, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, StakeInvestmentInfo, import("mongoose").Document<unknown, {}, StakeInvestmentInfo> & StakeInvestmentInfo & Required<{
    _id: string;
}>>;
