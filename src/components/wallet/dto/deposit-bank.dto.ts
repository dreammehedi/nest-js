import { ApiProperty } from "@nestjs/swagger";

export class DepositBankDTO {
    @ApiProperty()
    accountHolderName: string;

    @ApiProperty()
    accountNumber: string;

    @ApiProperty()
    bank: string;

    @ApiProperty()
    quote: string;
}