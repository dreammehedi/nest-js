import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiQuery, ApiTags } from '@nestjs/swagger';
import { User } from 'src/decorators/user.decorator';
import { AuthService } from './auth.service';
import { AddBannerDTO, GetBannerDTO, UpdateBannerDTO } from './dto/banner.dto';
import { EmailDTO } from './dto/email.dto';
import { LoginDTO } from './dto/login.dto';
import { OtpDTO } from './dto/otp.dto';
import {
  ChangeEmailDTO,
  ChangePasswordDTO,
  PasswordDTO,
} from './dto/password.dto';
import { UpdateProfileDTO } from './dto/profile.dto';
import { SignupDTO } from './dto/signup.dto';
import {
  GetUsersDTO,
  UpdateUserActiveDTO,
  UpdateUserRoleDTO,
} from './dto/users.dto';
import { JwtAdminGuard } from './jwt-admin.guard';
import { JwtAuthGuard } from './jwt-auth.guard';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() signupDto: SignupDTO) {
    signupDto.isAdmin = false;
    return this.authService.signup(signupDto);
  }

  @Post('signupAdmin')
  signupAdmin(@Body() signupDto: SignupDTO) {
    signupDto.isAdmin = true;
    return this.authService.signup(signupDto);
  }

  @Post('verifyEmail')
  verifyEmail(@Body() otpDto: OtpDTO) {
    return this.authService.verifyEmail(otpDto);
  }

  @Post('resendOtp')
  resendOtp(@Body() emailDto: EmailDTO) {
    return this.authService.resendOtp(emailDto);
  }

  @Post('login')
  login(@Body() loginDto: LoginDTO) {
    return this.authService.login(loginDto);
  }

  @Post('forgotPassword')
  forgotPassword(@Body() emailDto: EmailDTO) {
    return this.authService.forgotPassword(emailDto);
  }

  @Post('verifyOtpForForgotPassword')
  verifyOtpForForgotPassword(@Body() otpDto: OtpDTO) {
    return this.authService.verifyOtpForForgotPassword(otpDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('resetPassword')
  resetPassword(@Body() passwordDto: PasswordDTO, @User() user) {
    return this.authService.resetPassword(passwordDto, user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('changePassword')
  changePassword(@Body() changePasswordDTO: ChangePasswordDTO, @User() user) {
    return this.authService.changePassword(changePasswordDTO, user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('changeEmail')
  changeEmail(@Body() changeEmailDTO: ChangeEmailDTO, @User() user) {
    return this.authService.changeEmail(changeEmailDTO, user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('updateProfile')
  updateProfile(@Body() updateProfile: UpdateProfileDTO, @User() user) {
    return this.authService.updateProfile(updateProfile, user.id);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getLoggedInUser')
  getLoggedInUsers(@User() user) {
    return this.authService.getLoggedInUsers(user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('deleteUser')
  deleteUser(@User() user) {
    return this.authService.deleteUser(user?.id);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @ApiQuery({ name: 'limit', required: false, type: Number, example: 10 })
  @ApiQuery({ name: 'offset', required: false, type: Number, example: 0 })
  @Get('getAllUsers')
  getAllUsers(@User() User, @Query() getUsersDTO: GetUsersDTO) {
    return this.authService.getAllUsers(User?.id, getUsersDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('updateUserActive')
  updateUserActive(@Body() updateUserActiveDTO: UpdateUserActiveDTO) {
    return this.authService.updateUserActive(updateUserActiveDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('updateUserRole')
  updateUserRole(@Body() updateUserRoleDTO: UpdateUserRoleDTO) {
    return this.authService.updateUserRole(updateUserRoleDTO);
  }

  // @ApiBearerAuth()
  // @UseGuards(JwtAuthGuard)
  // @Get('enable2FA')
  // enable2FA(@User() user) {
  //     return this.authService.enable2FA(user?.id)
  // }

  // @ApiBearerAuth()
  // @UseGuards(JwtAuthGuard)
  // @Get('enable2FA/:otp')
  // validate2FA(@User() user, @Param("otp") otp: string) {
  //     return this.authService.validate2FA(user?.id, otp)
  // }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('addBanner')
  addBanner(@Body() addBannerDTO: AddBannerDTO) {
    return this.authService.addBanner(addBannerDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAdminGuard)
  @UseGuards(JwtAuthGuard)
  @Post('updateBanner')
  updateBanner(@Body() updateBannerDTO: UpdateBannerDTO) {
    return this.authService.updateBanner(updateBannerDTO);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('getBanners')
  getBanners(@Query() getBannerDTO: GetBannerDTO) {
    return this.authService.getBanners(getBannerDTO);
  }
}
