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
/// <reference types="mongoose" />
/// <reference types="mongoose/types/inferschematype" />
import { WalletService } from './wallet.service';
import { TransactionDTO, UpdateTransactionDTO } from './dto/transaction.dto';
import { NetworkDTO } from './dto/coinNetwork.dto';
import { SwapDTO, WithdrawDTO, WithdrawFiatDTO } from './dto/withdraw.dto';
import { Request } from 'express';
import { SetFeeDTO } from './dto/setFee.dto';
import { SendNftDTO } from './dto/send-nft.dto';
import { StakeDTO } from './dto/stake.dto';
import { WithdrawRewardDTO } from './dto/withdrawReward.dto';
import { AddDonationOrganizationDTO } from './dto/add-donation-organization.dto';
import { UpdateDonationOrganizationDTO } from './dto/update-donation-organization.dto';
import { DepositBankDTO } from './dto/deposit-bank.dto';
import { BuyCryptoDTO } from './dto/buy-crypto.dto';
import { TRANSACTIONSTATUSENUM } from 'src/enum/transaction.enum';
export declare class WalletController {
    private _walletService;
    constructor(_walletService: WalletService);
    getWalletWithBalance(user: any): Promise<{
        wallet: any;
        balance: any[];
    }>;
    getUserWalletWithBalance(userId: string): Promise<{
        wallet: any;
        balance: any[];
    }>;
    getDepositAddress(user: any, networkDTO: NetworkDTO): Promise<{
        address: string;
        publicKey: string;
    }>;
    withdraw(user: any, withdrawDTO: WithdrawDTO, req: Request): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
        _id: string;
    }>>;
    withdrawFiat(user: any, withdrawFiatDTO: WithdrawFiatDTO): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
        _id: string;
    }>>;
    getSwapQuote(swapDTO: SwapDTO, req: Request): Promise<{
        swappedAmount: number;
        swapFee: number;
        coinPrice: number;
    }>;
    swap(user: any, swapDTO: SwapDTO, req: Request): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
        _id: string;
    }>>;
    getTransactions(transactionDTO: TransactionDTO, user: any): Promise<any[]>;
    getTransactionsByAdmin(transactionDTO: TransactionDTO, user: any): Promise<any[]>;
    updateTransaction(updateTransactionDTO: UpdateTransactionDTO, user: any): Promise<{
        message: string;
    }>;
    getStats(): Promise<{
        totalUsers: number;
        activeUsers: number;
        newUsers: number;
        withdrawsFiat: number;
    }>;
    moralisTransactionWebHook(transactionDto: any): Promise<{
        message: string;
    }>;
    getNonce(address: string): Promise<{
        nonce: number;
        pending: number;
    }>;
    getFee(): Promise<(import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/FeeInfo/fee-info.schema").FeeInfo> & import("../../schema/FeeInfo/fee-info.schema").FeeInfo & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/FeeInfo/fee-info.schema").FeeInfo> & import("../../schema/FeeInfo/fee-info.schema").FeeInfo & Required<{
        _id: string;
    }>)[]>;
    setFee(setFeeDto: SetFeeDTO): Promise<{
        message: string;
    }>;
    getDepositBank(currency?: string): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/DepositBankDetail/deposit-bank-detail.schema").DepositBankDetail> & import("../../schema/DepositBankDetail/deposit-bank-detail.schema").DepositBankDetail & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/DepositBankDetail/deposit-bank-detail.schema").DepositBankDetail> & import("../../schema/DepositBankDetail/deposit-bank-detail.schema").DepositBankDetail & Required<{
        _id: string;
    }>>;
    updateDepositBank(id: string, depositBankDto: DepositBankDTO): Promise<{
        message: string;
    }>;
    getMytsionQuote(buyCryptoDto: BuyCryptoDTO): Promise<{
        fromCoinAmount: number;
        fromCoinAmountUsd: number;
        toCoinPrice: number;
        toCoinAmount: number;
        fee: number;
        feeInCoin: number;
    }>;
    buyCrypto(user: any, buyCryptoDto: BuyCryptoDTO): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
        _id: string;
    }>>;
    updateStatusOfBuyCryptoTransaction(id: string, status?: TRANSACTIONSTATUSENUM): Promise<{
        message: string;
    }>;
    sendNft(sendNftDto: SendNftDTO, user: any): Promise<{
        message: string;
    }>;
    stakeAmount(stakeDto: StakeDTO, user: any): Promise<{
        message: string;
        data: {
            hash: import("web3-types").Bytes;
        };
        transaction: import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
            _id: string;
        }>> & import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
            _id: string;
        }>;
    }>;
    getUserStakeData(coinId: string, limit: number, offset: number, user: any): Promise<any>;
    withdrawReward(withdrawRewardDto: WithdrawRewardDTO, user: any): Promise<{
        message: string;
        data: {
            hash: import("web3-types").Bytes;
        };
        transaction: import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
            _id: string;
        }>> & import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
            _id: string;
        }>;
    }>;
    unstakeInvestment(withdrawRewardDto: WithdrawRewardDTO, user: any): Promise<{
        message: string;
        data: {
            hash: import("web3-types").Bytes;
        };
        transaction: import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
            _id: string;
        }>> & import("mongoose").Document<unknown, {}, import("../../schema/Transaction/transaction.schema").Transaction> & import("../../schema/Transaction/transaction.schema").Transaction & Required<{
            _id: string;
        }>;
    }>;
    getStakingPlans(): Promise<{
        durationInDays: number;
        _id: string;
        __v?: any;
        $assertPopulated: <Paths = {}>(path: string | string[], values?: Partial<Paths>) => Omit<import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>, keyof Paths> & Paths;
        $clone: () => import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>;
        $getAllSubdocs: () => import("mongoose").Document<any, any, any>[];
        $ignore: (path: string) => void;
        $isDefault: (path: string) => boolean;
        $isDeleted: (val?: boolean) => boolean;
        $getPopulatedDocs: () => import("mongoose").Document<any, any, any>[];
        $inc: (path: string | string[], val?: number) => import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>;
        $isEmpty: (path: string) => boolean;
        $isValid: (path: string) => boolean;
        $locals: import("mongoose").FlattenMaps<Record<string, unknown>>;
        $markValid: (path: string) => void;
        $model: <ModelType = import("mongoose").Model<unknown, {}, {}, {}, import("mongoose").Document<unknown, {}, unknown> & Required<{
            _id: unknown;
        }>, any>>(name: string) => ModelType;
        $op: "remove" | "save" | "validate";
        $session: (session?: import("mongodb").ClientSession) => import("mongodb").ClientSession;
        $set: {
            (path: string | Record<string, any>, val: any, type: any, options?: import("mongoose").DocumentSetOptions): import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>;
            (path: string | Record<string, any>, val: any, options?: import("mongoose").DocumentSetOptions): import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>;
            (value: string | Record<string, any>): import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>;
        };
        $where: import("mongoose").FlattenMaps<Record<string, unknown>>;
        baseModelName?: string;
        collection: import("mongoose").Collection<import("bson").Document>;
        db: import("mongoose").FlattenMaps<import("mongoose").Connection>;
        deleteOne: (options?: import("mongoose").QueryOptions<unknown>) => Promise<import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>>;
        depopulate: (path?: string | string[]) => import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>;
        directModifiedPaths: () => string[];
        equals: (doc: import("mongoose").Document<unknown, any, any>) => boolean;
        errors?: import("mongoose").Error.ValidationError;
        get: {
            <T extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path: T, type?: any, options?: any): import("../../schema/StakingPlan/staking-plan.schema").StakingPlan[T];
            (path: string, type?: any, options?: any): any;
        };
        getChanges: () => import("mongoose").UpdateQuery<import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>>;
        id?: any;
        increment: () => import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>;
        init: (obj: import("mongoose").AnyObject, opts?: import("mongoose").AnyObject) => import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>;
        invalidate: {
            <T_1 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path: T_1, errorMsg: string | NativeError, value?: any, kind?: string): NativeError;
            (path: string, errorMsg: string | NativeError, value?: any, kind?: string): NativeError;
        };
        isDirectModified: {
            <T_2 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path: T_2 | T_2[]): boolean;
            (path: string | string[]): boolean;
        };
        isDirectSelected: {
            <T_3 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path: T_3): boolean;
            (path: string): boolean;
        };
        isInit: {
            <T_4 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path: T_4): boolean;
            (path: string): boolean;
        };
        isModified: {
            <T_5 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path?: T_5 | T_5[]): boolean;
            (path?: string | string[]): boolean;
        };
        isNew: boolean;
        isSelected: {
            <T_6 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path: T_6): boolean;
            (path: string): boolean;
        };
        markModified: {
            <T_7 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path: T_7, scope?: any): void;
            (path: string, scope?: any): void;
        };
        modifiedPaths: (options?: {
            includeChildren?: boolean;
        }) => string[];
        overwrite: (obj: import("mongoose").AnyObject) => import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>;
        $parent: () => import("mongoose").Document<any, any, any>;
        populate: {
            <Paths_1 = {}>(path: string | import("mongoose").PopulateOptions | (string | import("mongoose").PopulateOptions)[]): Promise<import("mongoose").MergeType<import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>, Paths_1>>;
            <Paths_2 = {}>(path: string, select?: string | import("mongoose").AnyObject, model?: import("mongoose").Model<any, {}, {}, {}, any, any>, match?: import("mongoose").AnyObject, options?: import("mongoose").PopulateOptions): Promise<import("mongoose").MergeType<import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>, Paths_2>>;
        };
        populated: (path: string) => any;
        replaceOne: (replacement?: import("mongoose").AnyObject, options?: import("mongoose").QueryOptions<unknown>) => import("mongoose").Query<any, import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>, {}, import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>, "find">;
        save: (options?: import("mongoose").SaveOptions) => Promise<import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>>;
        schema: import("mongoose").FlattenMaps<import("mongoose").Schema<any, import("mongoose").Model<any, any, any, any, any, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, {
            [x: string]: any;
        }, import("mongoose").Document<unknown, {}, {
            [x: string]: any;
        }> & {
            [x: string]: any;
        } & Required<{
            _id: unknown;
        }>>>;
        set: {
            <T_8 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path: T_8, val: import("../../schema/StakingPlan/staking-plan.schema").StakingPlan[T_8], type: any, options?: import("mongoose").DocumentSetOptions): import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>;
            (path: string | Record<string, any>, val: any, type: any, options?: import("mongoose").DocumentSetOptions): import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>;
            (path: string | Record<string, any>, val: any, options?: import("mongoose").DocumentSetOptions): import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>;
            (value: string | Record<string, any>): import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>;
        };
        toJSON: {
            <T_9 = import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>>(options?: import("mongoose").ToObjectOptions<import("mongoose").Document<unknown, {}, unknown> & Required<{
                _id: unknown;
            }>> & {
                flattenMaps?: true;
            }): import("mongoose").FlattenMaps<T_9>;
            <T_10 = import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
                _id: string;
            }>>(options: import("mongoose").ToObjectOptions<import("mongoose").Document<unknown, {}, unknown> & Required<{
                _id: unknown;
            }>> & {
                flattenMaps: false;
            }): T_10;
        };
        toObject: <T_11 = import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>>(options?: import("mongoose").ToObjectOptions<import("mongoose").Document<unknown, {}, unknown> & Required<{
            _id: unknown;
        }>>) => import("mongoose").Require_id<T_11>;
        unmarkModified: {
            <T_12 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(path: T_12): void;
            (path: string): void;
        };
        updateOne: (update?: import("mongoose").UpdateWithAggregationPipeline | import("mongoose").UpdateQuery<import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>>, options?: import("mongoose").QueryOptions<unknown>) => import("mongoose").Query<any, import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>, {}, import("mongoose").Document<unknown, {}, import("../../schema/StakingPlan/staking-plan.schema").StakingPlan> & import("../../schema/StakingPlan/staking-plan.schema").StakingPlan & Required<{
            _id: string;
        }>, "find">;
        validate: {
            <T_13 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(pathsToValidate?: T_13 | T_13[], options?: import("mongoose").AnyObject): Promise<void>;
            (pathsToValidate?: import("mongoose").PathsToValidate, options?: import("mongoose").AnyObject): Promise<void>;
            (options: {
                pathsToSkip?: import("mongoose").pathsToSkip;
            }): Promise<void>;
        };
        validateSync: {
            (options: {
                [k: string]: any;
                pathsToSkip?: import("mongoose").pathsToSkip;
            }): import("mongoose").Error.ValidationError;
            <T_14 extends keyof import("../../schema/StakingPlan/staking-plan.schema").StakingPlan>(pathsToValidate?: T_14 | T_14[], options?: import("mongoose").AnyObject): import("mongoose").Error.ValidationError;
            (pathsToValidate?: import("mongoose").PathsToValidate, options?: import("mongoose").AnyObject): import("mongoose").Error.ValidationError;
        };
        planId: number;
        duration: number;
        interestRate: number;
        isActive: boolean;
        stakingContractAddress: string;
        coinId: string;
        networkId: string;
    }[]>;
    addDonationOrganization(addDonationOrganizationDTO: AddDonationOrganizationDTO): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>>;
    updateDonationOrganization(id: string, updateDonationOrganizationDto: UpdateDonationOrganizationDTO): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>>;
    deleteDonationOrganization(id: string): Promise<import("mongoose").UpdateWriteOpResult>;
    getDonationOrganizations(limit?: number, offset?: number, name?: string): Promise<(import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>)[]>;
    getDonationOrganizationsForAdmin(limit?: number, offset?: number, name?: string): Promise<(import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>)[]>;
    getDonationOrganization(id: string): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization> & import("../../schema/DonationOrganization/donation-organization.schema").DonationOrganization & Required<{
        _id: string;
    }>>;
}
