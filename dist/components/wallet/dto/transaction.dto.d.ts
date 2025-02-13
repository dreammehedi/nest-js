export declare class TransactionDTO {
    userId?: string;
    limit: string;
    offset: string;
    type: string;
    status: string;
}
export declare class UpdateTransactionDTO {
    transactionId: string;
    status: string;
    trxUrl: string;
}
