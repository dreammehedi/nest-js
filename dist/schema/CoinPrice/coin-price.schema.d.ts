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
export type CoinPriceDocument = HydratedDocument<CoinPrice>;
export declare class CoinPrice {
    _id: string;
    coinId: string;
    networkId: string;
    currencyId: string;
    name: string;
    priceMarket: number;
    priceFormer: number;
    price: number;
    priceChange: number;
}
export declare const CoinPriceSchema: import("mongoose").Schema<CoinPrice, import("mongoose").Model<CoinPrice, any, any, any, import("mongoose").Document<unknown, any, CoinPrice> & CoinPrice & Required<{
    _id: string;
}>, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, CoinPrice, import("mongoose").Document<unknown, {}, CoinPrice> & CoinPrice & Required<{
    _id: string;
}>>;
