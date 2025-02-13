import { ApiProperty } from "@nestjs/swagger";

export class BuyCryptoDTO {
    @ApiProperty()
    paymentMethod: string;

    @ApiProperty({ required: false, enum: ['usd', 'ngn'] })
    fromCurrency: string;

    @ApiProperty()
    fromCoinId: string;

    @ApiProperty()
    amount: number;

    @ApiProperty()
    proofOfPayment: string
}