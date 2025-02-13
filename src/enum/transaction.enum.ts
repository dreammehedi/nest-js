export enum TRANSACTIONENUM {
  DEPOSIT = 'Deposit',
  SWAP = 'Swap',
  WITHDRAW = 'Withdraw',
  WITHDRAW_FIAT = 'Withdraw Fiat',
  STAKE = 'Stake',
  WITHDRAW_REWARD = 'Withdraw Reward',
  UNSTAKE = 'Unstake',
  BUY = 'Buy',
}

export enum TRANSACTIONSTATUSENUM {
  COMPLETED = 'Completed',
  PENDING = 'Pending',
  REJECTED = 'Rejected',
  PENDING_FROM_SYSTEM = 'Pending From System',
}
