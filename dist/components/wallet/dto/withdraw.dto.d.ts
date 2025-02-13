import { CoinNetworkDTO } from './coinNetwork.dto';
export declare class WithdrawDTO extends CoinNetworkDTO {
    address: string;
    amount: number;
}
export declare class SwapDTO extends CoinNetworkDTO {
    amount: number;
    currencyId: string;
}
export declare class WithdrawFiatDTO {
    amount: number;
    currencyId: string;
    bankName?: string;
    accountNumber?: string;
    accountName?: string;
    country?: string;
}
