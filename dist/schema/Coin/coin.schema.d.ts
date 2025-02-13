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
import { HydratedDocument } from 'mongoose';
export type CoinDocument = HydratedDocument<Coin>;
export declare class Coin {
    _id: string;
    name: string;
    symbol: string;
    icon: string;
    coinNameId: string;
    isToken: boolean;
    isStakingAvailable: boolean;
    contractAddress: string;
    stakingContractAddress: string;
    decimal: number;
    priceMarket: number;
    priceFormer: number;
    price: number;
    priceChange: number;
    swapFee: number;
    networkId: string;
    isDeleted: boolean;
    isActive: boolean;
    sort: number;
    unit: string;
    onRampId: string;
    onRampNetworkId: string;
    priceFrom: string;
}
export declare const CoinSchema: import("mongoose").Schema<Coin, import("mongoose").Model<Coin, any, any, any, import("mongoose").Document<unknown, any, Coin> & Coin & Required<{
    _id: string;
}>, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, Coin, import("mongoose").Document<unknown, {}, Coin> & Coin & Required<{
    _id: string;
}>>;
