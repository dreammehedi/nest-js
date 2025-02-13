import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiQuery, ApiTags } from '@nestjs/swagger';
import { WalletService } from './wallet.service';
import { User } from 'src/decorators/user.decorator';
import { TransactionDTO, UpdateTransactionDTO } from './dto/transaction.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { CoinNetworkDTO, NetworkDTO } from './dto/coinNetwork.dto';
import { SwapDTO, WithdrawDTO, WithdrawFiatDTO } from './dto/withdraw.dto';
import { JwtAdminGuard } from '../auth/jwt-admin.guard';
import { Request } from 'express';
import { SetFeeDTO } from './dto/setFee.dto';
import { SendNftDTO } from './dto/send-nft.dto';
import { StakeDTO } from './dto/stake.dto';
import { WithdrawRewardDTO } from './dto/withdrawReward.dto';
import { AddDonationOrganizationDTO } from './dto/add-donation-organization.dto';
import { UpdateDonationOrganizationDTO } from './dto/update-donation-organization.dto';
import { DepositBankDTO } from './dto/deposit-bank.dto';
import { BuyCryptoDTO } from './dto/buy-crypto.dto';
import { TRANSACTIONSTATUSENUM } from 'src/enum/transaction.enum';

@ApiTags('Wallet')
@Controller('wallet')
export class WalletController {
  constructor(private _walletService: WalletService) { }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getWalletWithBalance')
  getWalletWithBalance(@User() user) {
    return this._walletService.getWalletWithBalance(user.id);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Get('getUserWalletWithBalance/:userId')
  getUserWalletWithBalance(@Param('userId') userId: string) {
    return this._walletService.getWalletWithBalance(userId);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getDepositAddress')
  getDepositAddress(@User() user, @Query() networkDTO: NetworkDTO) {
    return this._walletService.getDepositAddress(user.id, networkDTO.networkId);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('withdraw')
  withdraw(
    @User() user,
    @Body() withdrawDTO: WithdrawDTO,
    @Req() req: Request,
  ) {
    req.setTimeout(20 * 60 * 1000);
    withdrawDTO.amount = Number(withdrawDTO.amount);
    return this._walletService.withdraw(user?.id, withdrawDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('withdrawFiat')
  withdrawFiat(@User() user, @Body() withdrawFiatDTO: WithdrawFiatDTO) {
    withdrawFiatDTO.amount = Number(withdrawFiatDTO.amount);
    return this._walletService.withdrawFiat(user.id, withdrawFiatDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('getSwapQuote')
  getSwapQuote(@Body() swapDTO: SwapDTO, @Req() req: Request) {
    req.setTimeout(20 * 60 * 1000);
    swapDTO.amount = Number(swapDTO.amount);
    return this._walletService.getQuote(swapDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('swap')
  swap(@User() user, @Body() swapDTO: SwapDTO, @Req() req: Request) {
    req.setTimeout(20 * 60 * 1000);
    swapDTO.amount = Number(swapDTO.amount);
    return this._walletService.swap(user.id, swapDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getTransactions')
  getTransactions(@Query() transactionDTO: TransactionDTO, @User() user) {
    transactionDTO.userId = user?.id;
    return this._walletService.getTransactions(transactionDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Get('getTransactionsByAdmin')
  getTransactionsByAdmin(
    @Query() transactionDTO: TransactionDTO,
    @User() user,
  ) {
    return this._walletService.getTransactionsByAdmin(transactionDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('updateTransaction')
  updateTransaction(
    @Body() updateTransactionDTO: UpdateTransactionDTO,
    @User() user,
  ) {
    return this._walletService.updateTransaction(updateTransactionDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Get('getStats')
  getStats() {
    return this._walletService.getStats();
  }

  @Post('moralisTransactionWebHook')
  async moralisTransactionWebHook(@Body() transactionDto) {
    console.log(
      '----------------------moralisTransactionWebHook----------------',
    );
    const wallet = await this._walletService.moralisTransactionWebHook(
      transactionDto,
    );
    return wallet;
  }

  @Get('getNonce/:address')
  getNonce(@Param('address') address: string) {
    return this._walletService.getNonce(address);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getFee')
  getFee() {
    return this._walletService.getFee();
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('setFee')
  setFee(@Body() setFeeDto: SetFeeDTO) {
    return this._walletService.setFee(setFeeDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiQuery({ name: 'currency', required: true, type: String, enum: ['usd', 'ngn'], example: 'usd' })
  @Get('getDepositBank')
  getDepositBank(
    @Query('currency') currency: string = 'usd',
  ) {
    return this._walletService.getDepositBank(
      currency,
    );
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('updateDepositBank/:id')
  updateDepositBank(@Param('id') id: string, @Body() depositBankDto: DepositBankDTO) {
    return this._walletService.updateDepositBank(id, depositBankDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('getMytsionQuote')
  getMytsionQuote(@Body() buyCryptoDto: BuyCryptoDTO) {
    return this._walletService.getMytsionQuote(buyCryptoDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('buyCrypto')
  buyCrypto(@User() user, @Body() buyCryptoDto: BuyCryptoDTO) {
    return this._walletService.buyCrypto(buyCryptoDto, user);
  }

  @ApiBearerAuth()
  // @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @ApiQuery({ name: 'status', required: false, type: String, enum: [TRANSACTIONSTATUSENUM.REJECTED, TRANSACTIONSTATUSENUM.COMPLETED] })
  @Post('updateStatusOfBuyCryptoTransaction/:id')
  updateStatusOfBuyCryptoTransaction(@Param('id') id: string, @Query('status') status: TRANSACTIONSTATUSENUM = TRANSACTIONSTATUSENUM.COMPLETED) {
    return this._walletService.updateStatusOfBuyCryptoTransaction(id, status);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('sendNft')
  sendNft(@Body() sendNftDto: SendNftDTO, @User() user) {
    return this._walletService.sendNft(sendNftDto, user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('stakeAmount')
  stakeAmount(@Body() stakeDto: StakeDTO, @User() user) {
    return this._walletService.stakeAmount(stakeDto, user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiQuery({ name: 'limit', required: false, type: Number, example: 10 })
  @ApiQuery({ name: 'offset', required: false, type: Number, example: 0 })
  @Get('getUserStakeData/:coinId')
  getUserStakeData(@Param('coinId') coinId: string, @Query('limit') limit = 10, @Query('offset') offset = 0, @User() user) {
    return this._walletService.getUserStakeData(coinId, limit, offset, user?.id);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('withdrawReward')
  withdrawReward(@Body() withdrawRewardDto: WithdrawRewardDTO, @User() user) {
    return this._walletService.withdrawReward(withdrawRewardDto, user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('unstakeInvestment')
  unstakeInvestment(@Body() withdrawRewardDto: WithdrawRewardDTO, @User() user) {
    return this._walletService.unstakeInvestment(withdrawRewardDto, user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getStakingPlans')
  getStakingPlans() {
    return this._walletService.getStakingPlans();
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('addDonationOrganization')
  addDonationOrganization(@Body() addDonationOrganizationDTO: AddDonationOrganizationDTO) {
    return this._walletService.addDonationOrganization(addDonationOrganizationDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('updateDonationOrganization/:id')
  updateDonationOrganization(@Param('id') id: string, @Body() updateDonationOrganizationDto: UpdateDonationOrganizationDTO) {
    return this._walletService.updateDonationOrganization(id, updateDonationOrganizationDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('deleteDonationOrganization/:id')
  deleteDonationOrganization(@Param('id') id: string) {
    return this._walletService.deleteDonationOrganization(id);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiQuery({ name: 'limit', required: false, type: Number, example: 10 })
  @ApiQuery({ name: 'offset', required: false, type: Number, example: 0 })
  @ApiQuery({ name: 'name', required: false, type: String })
  @Get('getDonationOrganizations')
  getDonationOrganizations(@Query('limit') limit = 10, @Query('offset') offset = 0, @Query('name') name: string = '') {
    return this._walletService.getDonationOrganizations(limit, offset, name);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @ApiQuery({ name: 'limit', required: false, type: Number, example: 10 })
  @ApiQuery({ name: 'offset', required: false, type: Number, example: 0 })
  @ApiQuery({ name: 'name', required: false, type: String })
  @Get('getDonationOrganizationsForAdmin')
  getDonationOrganizationsForAdmin(@Query('limit') limit = 10, @Query('offset') offset = 0, @Query('name') name: string = '') {
    return this._walletService.getDonationOrganizationsForAdmin(limit, offset, name);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getDonationOrganization/:id')
  getDonationOrganization(@Param('id') id: string) {
    return this._walletService.getDonationOrganization(id);
  }
}
