import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty } from "class-validator";

export class UpdateDonationOrganizationDTO {
    @ApiProperty()
    @IsNotEmpty()
    name: string;

    @ApiProperty()
    walletAddress: string;

    @ApiProperty()
    isActive: boolean;
}