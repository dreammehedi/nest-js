import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt/dist';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { encode } from 'hi-base32';
import { Model } from 'mongoose';
import * as otpGenerator from 'otp-generator';
import * as OTPAuth from 'otpauth';
import { Banner, BannerDocument } from 'src/schema/banner/banner.schema';
import {
  Currency,
  CurrencyDocument,
} from 'src/schema/Currency/currency.schema';
import { NFT, NFTDocument } from 'src/schema/Nft/nft.schema';
import { Otp, OtpDocument } from 'src/schema/OTP/otp.schema';
import { User, UserDocument } from 'src/schema/User/user.schema';
import { cleanObject } from 'src/utils/dto-transform';
import { OTPTYPEENUM } from '../../enum/otp.enum';
import { UserRoleENUM } from '../../enum/user.enum';
import { NftService } from '../nft/nft.service';
import { getEmail } from '../utils/email/dataEmail';
import { UtilsService } from '../utils/utils.service';
import { WalletService } from '../wallet/wallet.service';
import { AddBannerDTO, GetBannerDTO, UpdateBannerDTO } from './dto/banner.dto';
import { EmailDTO } from './dto/email.dto';
import { LoginDTO } from './dto/login.dto';
import { OtpDTO } from './dto/otp.dto';
import { ChangeEmailDTO, ChangePasswordDTO } from './dto/password.dto';
import { UpdateProfileDTO } from './dto/profile.dto';
import { SignupDTO } from './dto/signup.dto';
import {
  GetUsersDTO,
  UpdateUserActiveDTO,
  UpdateUserRoleDTO,
} from './dto/users.dto';
const crypto = require('crypto');

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    @InjectModel(User.name) private _userModel: Model<UserDocument>,
    @InjectModel(Otp.name) private _otpModel: Model<OtpDocument>,
    @InjectModel(Currency.name) private _currencyModel: Model<CurrencyDocument>,
    @InjectModel(NFT.name) private _nftModel: Model<NFTDocument>,
    @InjectModel(Banner.name) private _bannerModel: Model<BannerDocument>,
    private utilsService: UtilsService,
    private walletService: WalletService,
    private nftService: NftService,
  ) {
    this.init();
  }

  async init() {
    try {
      const superAdmin = await this._userModel.findOne({ isSuperAdmin: true });
      if (superAdmin) {
        await superAdmin.updateOne({
          email: process.env.SUPER_ADMIN_EMAIL,
          password: process.env.SUPER_ADMIN_PASSWORD,
          isActive: true,
          isVerified: true,
          isAdmin: true,
          isSuperAdmin: true,
        });
      } else {
        await new this._userModel({
          email: process.env.SUPER_ADMIN_EMAIL,
          password: process.env.SUPER_ADMIN_PASSWORD,
          isActive: true,
          isVerified: true,
          isAdmin: true,
          isSuperAdmin: true,
        }).save();
      }

      // const users = await this._userModel.find({});
      // for await (const user of users) {
      //     const ranHex = [...Array(20)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
      //     await user.updateOne({ authSecret: ranHex });
      // }
    } catch (err) {
      console.log(err);
    }
  }

  private generateToken(payload) {
    return {
      access_token: `Bearer ${this.jwtService.sign(payload)}`,
    };
  }

  async signup(signupDto: SignupDTO) {
    try {
      signupDto.email = signupDto?.email?.toLowerCase();

      const existingUser = await this._userModel.findOne({
        email: signupDto.email,
        isVerified: true,
        isDeleted: false,
      });
      if (existingUser) {
        throw new Error('User already exists with this email');
      }

      await this._userModel.deleteMany({
        email: signupDto?.email,
        isVerified: false,
      });

      const currency = await this._currencyModel.findOne({
        _id: signupDto.currencyId,
      });

      if (!currency) {
        throw new Error('Invalid currency');
      }

      const ranHex = [...Array(20)]
        .map(() => Math.floor(Math.random() * 16).toString(16))
        .join('');

      // const buffer = crypto.randomBytes(15);
      // const base32 = encode(buffer).replace(/=/g, "").substring(0, 20);

      signupDto.authSecret = ranHex;

      const userData = await new this._userModel(signupDto).save();

      const otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
      });

      const expiryTime = new Date(Date.now()).getTime() + 2 * 60 * 1000;

      const otpObject = {
        otp: otp,
        userId: userData.id,
        expiryTime: expiryTime,
        otpType: OTPTYPEENUM.VERIFY,
      };

      const expiredOtp = await this._otpModel.find({
        otpType: OTPTYPEENUM.VERIFY,
        userId: userData.id,
        expiryTime: { $lt: new Date(Date.now()).getTime() },
      });

      const currentTime = new Date(Date.now()).getTime();

      if (expiredOtp[0]) {
        if (currentTime > new Date(expiredOtp[0].expiryTime).getTime()) {
          await this._otpModel.findByIdAndUpdate(expiredOtp[0]._id, {
            isUsed: true,
          });
        }
      }

      const otpAlreadyPresent = await this._otpModel.find({
        isKYC: true,
        userId: userData.id,
        isUsed: false,
      });

      if (otpAlreadyPresent.length > 0) {
        await this._otpModel.findByIdAndUpdate(otpAlreadyPresent[0]._id, {
          isUsed: true,
        });
      }

      await this._otpModel.create(otpObject);

      const res = await this.utilsService.sendEmail({
        from: process.env.SENDER_MAIL,
        to: [signupDto?.email],
        subject: 'Confirm your email',
        html: getEmail(`${signupDto?.fullname}`, otp),
      });

      return { user: userData };
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err?.message);
    }
  }

  async resendOtp(emailDto: EmailDTO) {
    try {
      emailDto.email = emailDto?.email?.toLowerCase();
      const userData = await this._userModel.findOne({
        email: emailDto?.email,
        isDeleted: false,
      });

      if (!userData) {
        throw new Error('Invalid email');
      }

      if (userData?.isVerified) {
        //forgot password

        return await this.forgotPassword(emailDto);
      } else {
        //signup
        const otp = otpGenerator.generate(6, {
          upperCaseAlphabets: false,
          lowerCaseAlphabets: false,
          specialChars: false,
        });

        const expiryTime = new Date(Date.now()).getTime() + 2 * 60 * 1000;

        const otpObject = {
          otp: otp,
          userId: userData.id,
          expiryTime: expiryTime,
          otpType: OTPTYPEENUM.VERIFY,
        };

        const expiredOtp = await this._otpModel.find({
          otpType: OTPTYPEENUM.VERIFY,
          userId: userData.id,
          expiryTime: { $lt: new Date(Date.now()).getTime() },
        });

        const currentTime = new Date(Date.now()).getTime();

        if (expiredOtp[0]) {
          if (currentTime > new Date(expiredOtp[0].expiryTime).getTime()) {
            await this._otpModel.findByIdAndUpdate(expiredOtp[0]._id, {
              isUsed: true,
            });
          }
        }

        const otpAlreadyPresent = await this._otpModel.find({
          isKYC: true,
          userId: userData.id,
          isUsed: false,
        });

        if (otpAlreadyPresent.length > 0) {
          await this._otpModel.findByIdAndUpdate(otpAlreadyPresent[0]._id, {
            isUsed: true,
          });
        }

        await this._otpModel.create(otpObject);

        /*
                  Send email logic here
                */
        const res = await this.utilsService.sendEmail({
          from: process.env.SENDER_MAIL,
          to: [userData?.email],
          subject: 'Confirm your email',
          html: getEmail(userData.fullname, otp),
        });

        return { status: 'success', message: 'OTP resent' };
      }
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err?.message);
    }
  }

  async verifyEmail(otpDto: OtpDTO) {
    try {
      otpDto.email = otpDto?.email?.toLowerCase();

      const user = await this._userModel.findOne({
        email: otpDto?.email,
        isDeleted: false,
      });

      if (!user) {
        throw new Error('Invalid email');
      }

      if (user?.isVerified) {
        throw new Error('Email already verified');
      }

      const otp = await this._otpModel.findOne({
        userId: user.id,
        otp: otpDto?.otp,
        isUsed: false,
        otpType: OTPTYPEENUM.VERIFY,
      });

      if (!otp) {
        throw new Error('Wrong OTP typed');
      }

      const currentTime = new Date(Date.now()).getTime();

      if (currentTime > new Date(otp.expiryTime).getTime()) {
        await this._otpModel.findByIdAndUpdate(otp._id, { isUsed: true });
        throw new Error('Otp expired');
      }

      let isActive = !user.isAdmin;

      if (otp.isChangeEmail) {
        isActive = true;
      }

      await otp.updateOne({
        isUsed: true,
      });

      await this._userModel.updateOne(
        { _id: user.id },
        { isVerified: true, isActive: isActive },
      );

      let userData = await this._userModel.findOne({
        _id: user.id,
        isDeleted: false,
      });
      userData = JSON.parse(JSON.stringify(userData));

      delete userData.password;

      if (!otp.isChangeEmail) {
        await this.walletService.createWallet(userData.id);
      }

      const token = await this.generateToken(userData);

      return { status: 'success', token };
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err?.message);
    }
  }

  async login(loginDto: LoginDTO) {
    try {
      loginDto.email = loginDto.email.toLowerCase();
      let user = await this._userModel
        .aggregate([
          {
            $match: {
              email: loginDto.email,
              isVerified: true,
              isDeleted: false,
            },
          },
          {
            $lookup: {
              from: 'currencies',
              localField: 'currencyId',
              foreignField: '_id',
              as: 'currency',
            },
          },
          {
            $unwind: {
              path: '$currency',
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $addFields: {
              id: '$_id',
              'currency.id': '$currency._id',
            },
          },
          {
            $project: {
              _id: 0,
              'currency._id': 0,
            },
          },
        ])
        .then((res) => res[0]);
      if (!user) {
        throw new Error('Incorrect credentials');
      }

      if (await bcrypt.compare(loginDto.password, user.password)) {
        user = JSON.parse(JSON.stringify(user));
        delete user.password;

        const token = await this.generateToken(user);

        if (!user.isActive) {
          throw new Error('User is not active.');
        }

        return { user, token };
      } else {
        throw new Error('Incorrect credentials');
      }
    } catch (err) {
      console.log(err);
      throw new UnauthorizedException(err?.message);
    }
  }

  async forgotPassword(emailDto: EmailDTO) {
    try {
      emailDto.email = emailDto?.email?.toLowerCase();

      const user = await this._userModel.findOne({
        email: emailDto?.email,
        isDeleted: false,
      });

      if (!user) {
        throw new Error('Invalid Email');
      }

      const otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
      });

      const expiryTime = new Date(Date.now()).getTime() + 2 * 60 * 1000;

      // console.log(expiryTime);

      const otpObject = {
        otp: otp,
        userId: user.id,
        expiryTime: expiryTime,
        otpType: OTPTYPEENUM.FORGOT,
      };

      const expiredOtp = await this._otpModel.find({
        userId: user.id,
        expiryTime: { $lt: new Date(Date.now()).getTime() },
        otpType: OTPTYPEENUM.FORGOT,
      });

      const currentTime = new Date(Date.now()).getTime();

      if (expiredOtp[0]) {
        if (currentTime > new Date(expiredOtp[0].expiryTime).getTime()) {
          await this._otpModel.findByIdAndUpdate(expiredOtp[0]._id, {
            isUsed: true,
          });
        }
      }

      const otpAlreadyPresent = await this._otpModel.find({
        isKYC: true,
        userId: user.id,
        isUsed: false,
        otpType: OTPTYPEENUM.FORGOT,
      });

      if (otpAlreadyPresent.length > 0) {
        await this._otpModel.findByIdAndUpdate(otpAlreadyPresent[0]._id, {
          isUsed: true,
        });
      }

      await this._otpModel.create(otpObject);

      const res = await this.utilsService.sendEmail({
        from: process.env.SENDER_MAIL,
        to: [emailDto?.email],
        subject: 'Confirm your email',
        html: getEmail(user.fullname, otp, false),
      });

      return {
        status: 'success',
      };
    } catch (err) {
      throw new BadRequestException(err?.message);
    }
  }

  async verifyOtpForForgotPassword(otpDto: OtpDTO) {
    try {
      otpDto.email = otpDto?.email?.toLowerCase();
      let user: any = await this._userModel.findOne({
        email: otpDto?.email,
        isDeleted: false,
      });
      if (!user) {
        throw new Error('Invalid Email');
      }

      const otp = await this._otpModel.findOne({
        userId: user.id,
        otp: otpDto?.otp,
        isUsed: false,
        otpType: OTPTYPEENUM.FORGOT,
      });

      if (!otp) {
        throw new Error('Wrong OTP typed');
      }

      await otp.updateOne({
        isUsed: true,
      });

      const currentTime = new Date(Date.now()).getTime();

      if (currentTime > new Date(otp.expiryTime).getTime()) {
        await this._otpModel.findByIdAndUpdate(otp._id, { isUsed: true });
        throw new Error('Otp expired');
      }

      user = JSON.parse(JSON.stringify(user));

      delete user.password;

      user.isForgetPassword = true;

      const token = await this.generateToken(user);

      return { status: 'success', token };
    } catch (err) {
      throw new UnauthorizedException(err?.message);
    }
  }

  async resetPassword(resetPasswordDto, user) {
    try {
      // if (!user.isForgetPassword) {
      //     throw new UnauthorizedException('Cannot reset password at this stage');
      // }

      const userData = await this._userModel.findOne({
        _id: user.id,
        isDeleted: false,
      });

      if (!userData) {
        throw new UnauthorizedException('No user found');
      }

      await this._userModel.updateOne(
        { _id: user.id },
        { password: resetPasswordDto.password },
      );

      return { status: 'success' };
    } catch (err) {
      throw new UnauthorizedException(err.message);
    }
  }

  async changePassword(changePasswordDto: ChangePasswordDTO, user) {
    try {
      const userData = await this._userModel.findOne({
        _id: user.id,
        isDeleted: false,
      });

      if (!userData) {
        throw new UnauthorizedException('No user found');
      }

      if (
        await bcrypt.compare(changePasswordDto.oldPassword, userData.password)
      ) {
      } else {
        throw new Error('Old password is incorrect');
      }

      await this._userModel.updateOne(
        { _id: user.id },
        { password: changePasswordDto.password },
      );

      return { status: 'success' };
    } catch (err) {
      throw new UnauthorizedException(err.message);
    }
  }

  async changeEmail(changeEmailDto: ChangeEmailDTO, user) {
    try {
      changeEmailDto.email = changeEmailDto?.email?.toLowerCase();

      const existingUser = await this._userModel.findOne({
        email: changeEmailDto.email,
        isVerified: true,
        isDeleted: false,
      });
      if (existingUser) {
        throw new Error('User already exists with this email');
      }

      await this._userModel.deleteMany({
        email: changeEmailDto?.email,
        isVerified: false,
      });

      const userData = await this._userModel.findOne({
        _id: user.id,
        isDeleted: false,
      });

      if (userData.email != changeEmailDto.oldEmail) {
        throw new Error('Old email incorrect');
      }

      if (await bcrypt.compare(changeEmailDto.password, userData.password)) {
      } else {
        throw new Error('Incorrect credentials');
      }

      await userData.updateOne({
        email: changeEmailDto.email,
        isVerified: false,
      });

      const otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
      });

      const expiryTime = new Date(Date.now()).getTime() + 20 * 60 * 1000;

      const otpObject = {
        otp: otp,
        userId: userData.id,
        expiryTime: expiryTime,
        otpType: OTPTYPEENUM.VERIFY,
        isChangeEmail: true,
      };

      const expiredOtp = await this._otpModel.find({
        otpType: OTPTYPEENUM.VERIFY,
        userId: userData.id,
        expiryTime: { $lt: new Date(Date.now()).getTime() },
      });

      const currentTime = new Date(Date.now()).getTime();

      if (expiredOtp[0]) {
        if (currentTime > new Date(expiredOtp[0].expiryTime).getTime()) {
          await this._otpModel.findByIdAndUpdate(expiredOtp[0]._id, {
            isUsed: true,
          });
        }
      }

      const otpAlreadyPresent = await this._otpModel.find({
        isKYC: true,
        userId: userData.id,
        isUsed: false,
      });

      if (otpAlreadyPresent.length > 0) {
        await this._otpModel.findByIdAndUpdate(otpAlreadyPresent[0]._id, {
          isUsed: true,
        });
      }

      await this._otpModel.create(otpObject);

      const res = await this.utilsService.sendEmail({
        from: process.env.SENDER_MAIL,
        to: [changeEmailDto?.email],
        subject: 'Confirm your email',
        html: getEmail(userData.fullname, otp),
      });

      return { user: userData };
    } catch (err) {
      throw new UnauthorizedException(err.message);
    }
  }

  async updateProfile(updateProfile: UpdateProfileDTO, userId) {
    try {
      console.log(userId);
      Object.keys(updateProfile).forEach((key) => {
        if (updateProfile[key] === null) {
          delete updateProfile[key];
        }
      });
      console.log(updateProfile);

      if (updateProfile?.currencyId) {
        const currency = await this._currencyModel.findOne({
          _id: updateProfile?.currencyId,
        });

        if (!currency) {
          throw new Error('Invalid currency');
        }
      }

      const userData = await this._userModel.updateOne(
        { _id: userId },
        updateProfile,
      );

      return userData;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err?.message);
    }
  }

  async getLoggedInUsers(user) {
    try {
      const userData = await this._userModel
        .aggregate([
          {
            $match: {
              _id: user.id,
            },
          },
          {
            $lookup: {
              from: 'currencies',
              localField: 'currencyId',
              foreignField: '_id',
              as: 'currency',
            },
          },
          {
            $unwind: {
              path: '$currency',
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $addFields: {
              id: '$_id',
              'currency.id': '$currency._id',
            },
          },
          {
            $project: {
              _id: 0,
              password: 0,
            },
          },
        ])
        .then((res) => res[0]);

      const nft: any = await this._nftModel
        .findOne({
          userId: user.id,
        })
        .sort({ updatedAt: -1 });

      // fetch nfts if updatedAt is less than 1 hour
      if (
        new Date(nft?.updatedAt || 0).getTime() <
        new Date(Date.now()).getTime() - 5 * 60 * 1000
      ) {
        this.nftService.readNftForUser(user?.id);
      }

      return userData;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err?.message);
    }
  }

  async getAllUsers(userId, getUsersDTO: GetUsersDTO) {
    try {
      const userData = await this._userModel.findOne({
        _id: userId,
        isDeleted: false,
      });

      const offset = Number(getUsersDTO?.offset || 0);
      const limit = Number(getUsersDTO?.limit || 10);

      const filter = {
        isSuperAdmin: false,
        isVerified: true,
        isDeleted: false,
      };

      if (!userData.isSuperAdmin) {
        filter['isAdmin'] = false;
      }

      if (userData.isSuperAdmin && getUsersDTO.filterOnlyAdmins) {
        filter['isAdmin'] =
          getUsersDTO.filterOnlyAdmins === 'true' ||
          getUsersDTO.filterOnlyAdmins === true
            ? true
            : false;
      }

      if (!userData.isSuperAdmin && getUsersDTO.filterOnlyAdmins) {
        throw new Error('Unauthorized');
      }

      console.log(filter);
      const usersData = await this._userModel
        .find(filter)
        .sort({ createdAt: -1 })
        .skip(offset)
        .limit(limit);

      const users = usersData.map((userItem) => {
        const userReturnItem = JSON.parse(JSON.stringify(userItem));
        userReturnItem.role = userItem.isAdmin
          ? UserRoleENUM.ADMIN
          : UserRoleENUM.USER;
        return userReturnItem;
      });

      return users;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err?.message);
    }
  }

  async updateUserActive(updateUserActiveDTO: UpdateUserActiveDTO) {
    try {
      await this._userModel.updateOne(
        { _id: updateUserActiveDTO.userId },
        {
          isActive: updateUserActiveDTO.isActive,
        },
      );

      return {
        message: 'success',
      };
    } catch (err) {
      console.log(err?.message);
      throw new BadRequestException(err?.message);
    }
  }

  async updateUserRole(updateUserRoleDTO: UpdateUserRoleDTO) {
    try {
      const isAdmin =
        updateUserRoleDTO.role == UserRoleENUM.ADMIN ? true : false;
      await this._userModel.updateOne(
        { _id: updateUserRoleDTO.userId },
        {
          isAdmin: isAdmin,
        },
      );

      return {
        message: 'success',
      };
    } catch (err) {
      console.log(err?.message);
      throw new BadRequestException(err?.message);
    }
  }

  async enable2FA(userId) {
    const userDocument = await this._userModel.findOne({
      _id: userId,
      isDeleted: false,
    });

    const buffer = crypto.randomBytes(15);
    const base32 = encode(buffer).replace(/=/g, '').substring(0, 20);

    const totp = new OTPAuth.TOTP({
      issuer: 'cryptowallet.io',
      label: 'cryptowallet',
      algorithm: 'SHA1',
      digits: 6,
      secret: base32,
    });

    const url = totp.toString();

    await userDocument.updateOne({
      authSecret: base32,
      isAuthEnabled: true,
      authUrl: url,
    });

    return {
      authSecret: base32,
      isAuthEnabled: true,
      authUrl: url,
    };
  }

  async validate2FA(userId, otp) {
    const userDocument = await this._userModel.findOne({
      _id: userId,
      isDeleted: false,
    });

    const buffer = crypto.randomBytes(15);
    const base32 = encode(buffer).replace(/=/g, '').substring(0, 24);

    const totp = new OTPAuth.TOTP({
      issuer: 'cryptowallet.io',
      label: 'cryptowallet',
      algorithm: 'SHA1',
      digits: 6,
      secret: userDocument.authSecret,
    });

    const validateResponse = totp.validate({ token: otp, window: 1 });

    console.log(validateResponse);

    if (!validateResponse) {
      return {
        isValid: false,
      };
    }

    return {
      isValid: true,
    };
  }

  async deleteUser(userId) {
    await this._userModel.updateOne({ _id: userId }, { isDeleted: true });
    return { status: 'success', message: 'User Deleted' };
  }

  async addBanner(addBannerDTO: AddBannerDTO) {
    try {
      const bannerDocument = await new this._bannerModel(addBannerDTO).save();
      return bannerDocument;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err?.message);
    }
  }

  async updateBanner(updateBannerDTO: UpdateBannerDTO) {
    try {
      updateBannerDTO = cleanObject(updateBannerDTO);

      const bannerDocumentUpdate = await this._bannerModel.updateOne(
        {
          _id: updateBannerDTO.bannerId,
        },
        updateBannerDTO,
      );

      const bannerDocument = await this._bannerModel.findOne({
        _id: updateBannerDTO.bannerId,
      });

      return bannerDocument;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err?.message);
    }
  }

  async getBanners(getBannerDTO: GetBannerDTO) {
    try {
      let filter = {
        isDeleted: false,
      };

      if (getBannerDTO.isDeleted) {
        filter['isDeleted'] = getBannerDTO.isDeleted == 'true' ? true : false;
      }

      if (getBannerDTO.isActive) {
        filter['isActive'] = getBannerDTO.isActive == 'true' ? true : false;
      }

      console.log(filter);

      let limit = getBannerDTO.limit ? Number(getBannerDTO.limit) : 10;
      let offset = getBannerDTO.offset ? Number(getBannerDTO.offset) : 0;

      let pagination = [{ $skip: offset }, { $limit: limit }];

      const bannerDocuments = await this._bannerModel.aggregate([
        {
          $match: filter,
        },
        { $addFields: { id: '$_id' } },
        {
          $project: {
            _id: 0,
            id: 1,
            mediaUrl: 1,
            isActive: 1,
            isDeleted: 1,
          },
        },
        { $sort: { createdAt: -1 } },
        ...pagination,
      ]);

      return bannerDocuments;
    } catch (err) {
      console.log(err);
      throw new BadRequestException(err?.message);
    }
  }
}
