import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty } from "class-validator";

export class AddDonationOrganizationDTO {
    @ApiProperty()
    @IsNotEmpty()
    name: string;

    @ApiProperty()
    walletAddress: string;
}