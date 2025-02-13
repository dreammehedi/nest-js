import { InvestAmountDTO } from './dto/invest-amount.dto';
export declare class StakeService {
    private stakingContract;
    private coinContract;
    private web3;
    constructor(stakingContractAddress: string, rpc: string, coinAddress: string);
    getCurrentInvestmentId(): Promise<number>;
    getStakingPlans(): Promise<{
        id: number;
        duration: number;
        interestRate: number;
        isActive: boolean;
    }[]>;
    getStakingInformation(): Promise<{
        totalInvestments: number;
        totalStaked: number;
        totalRewards: number;
    }>;
    getUserStakingInformation(userAddress: string): Promise<{
        totalInvestments: number;
        totalStaked: number;
        totalRewards: number;
        investmentIds: any;
    }>;
    getStakingInformations(investmentIds: number[]): Promise<{
        id: number;
        planId: number;
        investor: any;
        amount: number;
        startDate: number;
        endDate: number;
        isClaimed: boolean;
        isWithdrawn: boolean;
        userId: string;
        stakingContractAddress: any;
        totalReward: number;
        dailyReward: number;
    }[]>;
    getAllStakingInformation(startIndex?: number): Promise<{
        id: number;
        planId: number;
        investor: any;
        amount: number;
        startDate: number;
        endDate: number;
        isClaimed: boolean;
        isWithdrawn: boolean;
        userId: string;
        stakingContractAddress: any;
        totalReward: number;
        dailyReward: number;
    }[]>;
    approve(amount: number, walletAddress: string, privateKey: string): Promise<any>;
    investAmount(investAmountDto: InvestAmountDTO): Promise<any>;
}
