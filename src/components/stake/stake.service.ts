import { Injectable, Scope } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Coin } from 'src/schema/Coin/coin.schema';
import { abi, fromWei, sleep } from 'src/utils/utils';
import { Web3 } from 'web3';
import { InvestAmountDTO } from './dto/invest-amount.dto';

export class StakeService {
    private stakingContract: any;
    private coinContract: any;
    private web3: any;
    constructor(
        stakingContractAddress: string,
        rpc: string,
        coinAddress: string,
    ) {
        console.log('StakeService constructor', stakingContractAddress, rpc, coinAddress);

        this.web3 = new Web3(rpc);
        this.stakingContract = new this.web3.eth.Contract(abi.staking, stakingContractAddress);
        this.coinContract = new this.web3.eth.Contract(abi.token, coinAddress);

    }

    async getCurrentInvestmentId() {
        try {
            const currentInvestmentId = await this.stakingContract.methods.investmentId().call();
            return Number(currentInvestmentId);
        } catch (error) {
            throw new Error(error);
        }
    }

    async getStakingPlans() {
        try {
            const currentPlanId = await this.stakingContract.methods.investmentPlanId().call();

            const planIds = Array.from({ length: Number(currentPlanId) }, (_, i) => i + 1);

            const planPromises = await Promise.all(planIds.map(async (planId) => {
                const plan = await this.stakingContract.methods.investmentPlans(planId).call();
                debugger
                return {
                    id: Number(plan?.id),
                    duration: Number(plan?.duration) * 1000,
                    interestRate: Number(plan?.interest) / 100,
                    isActive: Number(plan?.isActive) === 1
                };
            }));

            return planPromises;
        } catch (error) {
            throw new Error(error);
        }
    }

    async getStakingInformation() {
        try {
            const [
                totalInvestments,
                totalStaked,
                totalRewards,
            ] = await Promise.all([
                this.stakingContract.methods.totalInvestments().call(),
                this.stakingContract.methods.totalStaked().call(),
                this.stakingContract.methods.totalRewards().call()
            ]);

            return {
                totalInvestments: Number(totalInvestments) || 0,
                totalStaked: Number(fromWei(totalStaked?.toString(), 18)) || 0,
                totalRewards: Number(fromWei(totalRewards?.toString(), 18)) || 0,
            };
        }
        catch (error) {
            throw new Error(error);
        }
    }

    async getUserStakingInformation(userAddress: string) {
        try {
            const [investorData, investmentIds] = await Promise.all([
                this.stakingContract.methods.getInvestor(userAddress).call(),
                this.stakingContract.methods.getUserInvestmentIds(userAddress).call()?.then((investments) => {
                    return investments.map((investment) => {
                        return Number(investment);
                    });
                }),
            ]);

            return {
                totalInvestments: Number(investorData?.totalInvestments) || 0,
                totalStaked: Number(fromWei(investorData?.totalStaked?.toString(), 18)) || 0,
                totalRewards: Number(fromWei(investorData?.totalRewards?.toString(), 18)) || 0,
                investmentIds: investmentIds || [],
            };
        }
        catch (error) {
            throw new Error(error);
        }
    }

    async getStakingInformations(investmentIds: number[]) {
        try {
            const plans = await this.getStakingPlans();
            const investments = await Promise.all(investmentIds.map(async (investmentId) => {
                const investment = await this.stakingContract.methods.investments(investmentId).call();
                const currentPlan = plans.find((plan) => plan?.id === Number(investment?.planId));

                const totalRewardAfterCompletion = Number(investment?.isClaimed) === 0 && Number(investment?.isWithdrawn) === 0 ?
                    (Number(fromWei(investment?.amount?.toString(), 18)) * currentPlan?.interestRate) / 100 : 0

                const dailyReward = Number(investment?.isClaimed) === 0 && Number(investment?.isWithdrawn) === 0 ?
                    totalRewardAfterCompletion / (currentPlan?.duration / (1000 * 60 * 60 * 24)) : 0;

                return {
                    id: Number(investment?.id),
                    planId: Number(investment?.planId),
                    investor: investment?.user?.toLowerCase(),
                    amount: Number(fromWei(investment?.amount?.toString(), 18)),
                    startDate: Number(investment?.start) * 1000,
                    endDate: (Number(investment?.start) * 1000) + currentPlan?.duration,
                    isClaimed: Number(investment?.isClaimed) === 1,
                    isWithdrawn: Number(investment?.isWithdrawn) === 1,
                    userId: '',
                    stakingContractAddress: this?.stakingContract?.options?.address,
                    totalReward: totalRewardAfterCompletion,
                    dailyReward: dailyReward,
                }
            }));

            return investments;
        }
        catch (error) {
            throw new Error(error);
        }
    }

    async getAllStakingInformation(startIndex = 1) {
        try {
            const plans = await this.getStakingPlans();

            const currentInvestmentId = await this.stakingContract.methods.investmentId().call();

            const investmentIds = Array.from({ length: Number(currentInvestmentId) }, (_, i) => i + 1)?.slice(startIndex - 1);

            const investments = await Promise.all(investmentIds.map(async (investmentId) => {
                const investment = await this.stakingContract.methods.investments(investmentId).call();
                const currentPlan = plans.find((plan) => plan?.id === Number(investment?.planId));

                const totalRewardAfterCompletion = Number(investment?.isClaimed) === 0 && Number(investment?.isWithdrawn) === 0 ?
                    (Number(fromWei(investment?.amount?.toString(), 18)) * currentPlan?.interestRate) / 100 : 0

                const dailyReward = Number(investment?.isClaimed) === 0 && Number(investment?.isWithdrawn) === 0 ?
                    totalRewardAfterCompletion / (currentPlan?.duration / (1000 * 60 * 60 * 24)) : 0;

                return {
                    id: Number(investment?.id),
                    planId: Number(investment?.planId),
                    investor: investment?.user?.toLowerCase(),
                    amount: Number(fromWei(investment?.amount?.toString(), 18)),
                    startDate: Number(investment?.start) * 1000,
                    endDate: (Number(investment?.start) * 1000) + currentPlan?.duration,
                    isClaimed: Number(investment?.isClaimed) === 1,
                    isWithdrawn: Number(investment?.isWithdrawn) === 1,
                    userId: '',
                    stakingContractAddress: this?.stakingContract?.options?.address,
                    totalReward: totalRewardAfterCompletion,
                    dailyReward: dailyReward,
                }
            }));

            return investments;
        }
        catch (error) {
            throw new Error(error);
        }
    }

    async approve(amount: number, walletAddress: string, privateKey: string) {
        try {
            const fromAddress = walletAddress;

            const amountInWei = this.web3.utils.toWei(String(amount), 'ether');
            debugger
            const allowance = await this.coinContract.methods.allowance(fromAddress, this.stakingContract.options.address).call();
            debugger
            if (allowance >= BigInt(amountInWei)) {
                return;
            }
            debugger
            let nonce = await this.web3.eth.getTransactionCount(fromAddress);
            debugger
            let noncePending = await this.web3.eth.getTransactionCount(
                fromAddress,
                'pending',
            );

            while (Number(nonce) != Number(noncePending)) {
                console.log(
                    'waiting 10s for correct nonce...',
                    Number(nonce),
                    Number(noncePending),
                );
                await new Promise((resolve) => {
                    setTimeout(resolve, 10000);
                });
                nonce = await this.web3.eth.getTransactionCount(fromAddress);
                noncePending = await this.web3.eth.getTransactionCount(
                    fromAddress,
                    'pending',
                );
            }

            const gasPrice = await this.web3.eth.getGasPrice();
            debugger
            const gasLimit = await this.coinContract.methods
                .approve(this.stakingContract.options.address, amountInWei)
                .estimateGas({
                    from: fromAddress,
                });
            debugger
            const tx = {
                from: fromAddress,
                to: this.coinContract.options.address,
                // gas: gasLimit,
                // gasPrice: gasPrice,
                data: this.coinContract.methods
                    .approve(this.stakingContract.options.address, amountInWei)
                    .encodeABI(),
                nonce: nonce,
                value: 0,
            };
            debugger
            const signedTx = await this.web3.eth.accounts.signTransaction(tx, privateKey);

            const receipt = await this.web3.eth.sendSignedTransaction(signedTx.rawTransaction);

            return receipt;
        } catch (error) {
            debugger
            throw new Error(error?.message);
        }
    }

    async investAmount(investAmountDto: InvestAmountDTO) {
        try {
            if (!investAmountDto?.amount || !investAmountDto?.walletAddress || !investAmountDto?.privateKey) {
                throw new Error('Invalid input');
            }
            debugger
            const fromAddress = investAmountDto?.walletAddress;
            debugger
            const amount = this.web3.utils.toWei(String(investAmountDto?.amount), 'ether');
            debugger
            const privateKey = investAmountDto?.privateKey;
            debugger
            await this.approve(investAmountDto?.amount, fromAddress, privateKey);
            await sleep(2 * 1000);
            debugger
            let nonce = await this.web3.eth.getTransactionCount(fromAddress);
            let noncePending = await this.web3.eth.getTransactionCount(
                fromAddress,
                'pending',
            );
            debugger;
            while (Number(nonce) != Number(noncePending)) {
                console.log(
                    'waiting 10s for correct nonce...',
                    Number(nonce),
                    Number(noncePending),
                );
                await new Promise((resolve) => {
                    setTimeout(resolve, 10000);
                });
                nonce = await this.web3.eth.getTransactionCount(fromAddress);
                noncePending = await this.web3.eth.getTransactionCount(
                    fromAddress,
                    'pending',
                );
            }

            let gasPrice = await this.web3.eth.getGasPrice();

            let gasLimit = await this.stakingContract.methods
                .invest(investAmountDto?.planId, amount)
                .estimateGas({ from: fromAddress, value: amount });

            gasLimit = Math.floor(Number(gasLimit) * 1.2);
            gasPrice = Math.floor(Number(gasPrice) * 1.2);

            const gasAmountToBeDeducted = gasLimit * gasPrice;

            const balance = await this.web3.eth.getBalance(fromAddress);

            if (Number(balance) < Number(amount) + Number(gasAmountToBeDeducted)) {
                throw new Error('Insufficient balance');
            }

            const tx = {
                from: fromAddress,
                to: this.stakingContract.options.address,
                gas: gasLimit,
                gasPrice: gasPrice,
                data: this.stakingContract.methods
                    .invest(investAmountDto?.planId, amount)
                    .encodeABI(),
                nonce: nonce,
            };

            const signedTx = await this.web3.eth.accounts.signTransaction(tx, privateKey);

            const receipt = await this.web3.eth.sendSignedTransaction(signedTx.rawTransaction);

            return receipt;
        } catch (error) {
            console.log(error);
            throw new Error(error);
        }
    }

}
