/// <reference types="mongoose/types/aggregate" />
/// <reference types="mongoose/types/callback" />
/// <reference types="mongoose/types/collection" />
/// <reference types="mongoose/types/connection" />
/// <reference types="mongoose/types/cursor" />
/// <reference types="mongoose/types/document" />
/// <reference types="mongoose/types/error" />
/// <reference types="mongoose/types/expressions" />
/// <reference types="mongoose/types/helpers" />
/// <reference types="mongoose/types/middlewares" />
/// <reference types="mongoose/types/indexes" />
/// <reference types="mongoose/types/models" />
/// <reference types="mongoose/types/mongooseoptions" />
/// <reference types="mongoose/types/pipelinestage" />
/// <reference types="mongoose/types/populate" />
/// <reference types="mongoose/types/query" />
/// <reference types="mongoose/types/schemaoptions" />
/// <reference types="mongoose/types/schematypes" />
/// <reference types="mongoose/types/session" />
/// <reference types="mongoose/types/types" />
/// <reference types="mongoose/types/utility" />
/// <reference types="mongoose/types/validation" />
/// <reference types="mongoose/types/virtuals" />
/// <reference types="mongoose/types/inferschematype" />
import { JwtService } from '@nestjs/jwt/dist';
import { Model } from 'mongoose';
import { LoginDTO } from './dto/login.dto';
import { OtpDTO } from './dto/otp.dto';
import { UtilsService } from '../utils/utils.service';
import { SignupDTO } from './dto/signup.dto';
import { EmailDTO } from './dto/email.dto';
import { UpdateProfileDTO } from './dto/profile.dto';
import { User, UserDocument } from 'src/schema/User/user.schema';
import { OtpDocument } from 'src/schema/OTP/otp.schema';
import { WalletService } from '../wallet/wallet.service';
import { GetUsersDTO, UpdateUserActiveDTO, UpdateUserRoleDTO } from './dto/users.dto';
import { ChangeEmailDTO, ChangePasswordDTO } from './dto/password.dto';
import { CurrencyDocument } from 'src/schema/Currency/currency.schema';
import { NFTDocument } from 'src/schema/Nft/nft.schema';
import { NftService } from '../nft/nft.service';
import { Banner, BannerDocument } from 'src/schema/banner/banner.schema';
import { AddBannerDTO, GetBannerDTO, UpdateBannerDTO } from './dto/banner.dto';
export declare class AuthService {
    private jwtService;
    private _userModel;
    private _otpModel;
    private _currencyModel;
    private _nftModel;
    private _bannerModel;
    private utilsService;
    private walletService;
    private nftService;
    constructor(jwtService: JwtService, _userModel: Model<UserDocument>, _otpModel: Model<OtpDocument>, _currencyModel: Model<CurrencyDocument>, _nftModel: Model<NFTDocument>, _bannerModel: Model<BannerDocument>, utilsService: UtilsService, walletService: WalletService, nftService: NftService);
    init(): Promise<void>;
    private generateToken;
    signup(signupDto: SignupDTO): Promise<{
        user: import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, User> & User & Required<{
            _id: string;
        }>> & import("mongoose").Document<unknown, {}, User> & User & Required<{
            _id: string;
        }>;
    }>;
    resendOtp(emailDto: EmailDTO): Promise<{
        status: string;
    } | {
        status: string;
        message: string;
    }>;
    verifyEmail(otpDto: OtpDTO): Promise<{
        status: string;
        token: {
            access_token: string;
        };
    }>;
    login(loginDto: LoginDTO): Promise<{
        user: any;
        token: {
            access_token: string;
        };
    }>;
    forgotPassword(emailDto: EmailDTO): Promise<{
        status: string;
    }>;
    verifyOtpForForgotPassword(otpDto: OtpDTO): Promise<{
        status: string;
        token: {
            access_token: string;
        };
    }>;
    resetPassword(resetPasswordDto: any, user: any): Promise<{
        status: string;
    }>;
    changePassword(changePasswordDto: ChangePasswordDTO, user: any): Promise<{
        status: string;
    }>;
    changeEmail(changeEmailDto: ChangeEmailDTO, user: any): Promise<{
        user: import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, User> & User & Required<{
            _id: string;
        }>> & import("mongoose").Document<unknown, {}, User> & User & Required<{
            _id: string;
        }>;
    }>;
    updateProfile(updateProfile: UpdateProfileDTO, userId: any): Promise<import("mongoose").UpdateWriteOpResult>;
    getLoggedInUsers(user: any): Promise<any>;
    getAllUsers(userId: any, getUsersDTO: GetUsersDTO): Promise<any[]>;
    updateUserActive(updateUserActiveDTO: UpdateUserActiveDTO): Promise<{
        message: string;
    }>;
    updateUserRole(updateUserRoleDTO: UpdateUserRoleDTO): Promise<{
        message: string;
    }>;
    enable2FA(userId: any): Promise<{
        authSecret: string;
        isAuthEnabled: boolean;
        authUrl: string;
    }>;
    validate2FA(userId: any, otp: any): Promise<{
        isValid: boolean;
    }>;
    deleteUser(userId: any): Promise<{
        status: string;
        message: string;
    }>;
    addBanner(addBannerDTO: AddBannerDTO): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, Banner> & Banner & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, Banner> & Banner & Required<{
        _id: string;
    }>>;
    updateBanner(updateBannerDTO: UpdateBannerDTO): Promise<import("mongoose").Document<unknown, {}, import("mongoose").Document<unknown, {}, Banner> & Banner & Required<{
        _id: string;
    }>> & import("mongoose").Document<unknown, {}, Banner> & Banner & Required<{
        _id: string;
    }>>;
    getBanners(getBannerDTO: GetBannerDTO): Promise<any[]>;
}
