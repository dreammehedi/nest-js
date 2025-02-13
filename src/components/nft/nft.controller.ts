import { Controller, Get, Param, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiQuery, ApiTags } from '@nestjs/swagger';
import { NftService } from './nft.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { User } from 'src/decorators/user.decorator';

@ApiTags('NFT')
@Controller('nft')
export class NftController {
  constructor(private nftService: NftService) {}

  @ApiQuery({ name: 'limit', required: false, type: Number, example: 10 })
  @ApiQuery({ name: 'offset', required: false, type: Number, example: 0 })
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getNfts')
  async getNfts(
    @Query('limit') limit = 10,
    @Query('offset') offset = 0,
    @User() user,
  ) {
    return this.nftService.getNfts(limit, offset, user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getNftById/:id')
  async getNftById(@Param('id') id: string) {
    return this.nftService.getNftById(id);
  }
}
