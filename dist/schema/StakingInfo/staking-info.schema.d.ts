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
export type StakingInfoDocument = HydratedDocument<StakingInfo>;
export declare class StakingInfo {
    _id: string;
    totalInvestments: number;
    totalStaked: number;
    totalReward: number;
    stakingContractAddress: string;
    coinId: string;
    networkId: string;
}
export declare const StakingInfoSchema: import("mongoose").Schema<StakingInfo, import("mongoose").Model<StakingInfo, any, any, any, import("mongoose").Document<unknown, any, StakingInfo> & StakingInfo & Required<{
    _id: string;
}>, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, StakingInfo, import("mongoose").Document<unknown, {}, StakingInfo> & StakingInfo & Required<{
    _id: string;
}>>;
