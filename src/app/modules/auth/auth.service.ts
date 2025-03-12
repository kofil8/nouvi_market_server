import * as bcrypt from 'bcrypt';
import httpStatus from 'http-status';
import { Secret } from 'jsonwebtoken';
import config from '../../../config';
import prisma from '../../helpers/prisma';
import ApiError from '../../errors/ApiError';
import { generateOtpReg } from '../../utils/otpGenerateReg';
import { generateToken } from '../../utils/generateToken';
import { Status, UserRole } from '@prisma/client';
import { stripe } from '../../utils/stripe';

interface socialLoginPayload {
  email: string;
  role?: UserRole | undefined;
  name?: string;
  fcmToken?: string;
}
const loginUserFromDB = async (payload: {
  email: string;
  password: string;
  fcmToken?: string;
}) => {
  const userData = await prisma.user.findUnique({
    where: {
      email: payload.email,
    },
  });

  if (userData?.status == Status.INACTIVE) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User is inactive');
  }

  if (!userData) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User not found');
  }

  // check is user is verified
  if (!userData.isVerified) {
    const { otp, otpExpiry } = await generateOtpReg({ email: payload.email });

    await prisma.otp.create({
      data: {
        email: payload.email,
        otp,
        expiry: otpExpiry,
      },
    });

    throw new ApiError(
      httpStatus.TEMPORARY_REDIRECT,
      'User is not verified, Please verify your email first',
    );
  }

  const isCorrectPassword = await bcrypt.compare(
    payload.password,
    userData.password as string,
  );

  if (!isCorrectPassword) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Invalid credentials');
  }

  if (userData.isOnline === false) {
    await prisma.user.update({
      where: {
        email: payload.email,
      },
      data: {
        isOnline: true,
      },
    });
  }

  if (payload?.fcmToken) {
    await prisma.user.update({
      where: {
        email: payload.email,
      },
      data: {
        fcmToken: payload.fcmToken,
      },
    });
  }

  //  check if user is verified
  const accessToken = generateToken(
    {
      id: userData.id,
      email: userData.email as string,
      role: userData.role,
      isOnline: userData.isOnline,
    },
    config.jwt.jwt_secret as Secret,
    config.jwt.expires_in as string,
  );
  return {
    accessToken,
    id: userData.id,
    email: userData.email,
    role: userData.role,
  };
};

const socialLogin = async (payload: socialLoginPayload) => {
  const { email, role, name, fcmToken } = payload;

  const user = await prisma.user.findUnique({
    where: { email },
  });

  let isNewUser = false;

  if (!user) {
    const newUser = await prisma.user.create({
      data: {
        email,
        role,
        name,
        isVerified: true,
        isOnline: true,
        fcmToken: fcmToken || undefined,
      },
    });

    const stripeCustomer = await stripe.customers.create({
      email: newUser.email,
      name: newUser.name,
    });

    await prisma.user.update({
      where: { email: newUser.email },
      data: { stripeCustomerId: stripeCustomer.id },
    });

    isNewUser = true;

    const accessToken = generateToken(
      {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
        isOnline: newUser.isOnline,
      },
      config.jwt.jwt_secret as Secret,
      config.jwt.expires_in as string,
    );

    return {
      isNewUser,
      accessToken,
      id: newUser.id,
      email: newUser.email,
      role: newUser.role,
    };
  }

  await prisma.user.update({
    where: { email },
    data: {
      fcmToken: fcmToken || undefined,
      isOnline: true,
    },
  });

  const accessToken = generateToken(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      isOnline: user.isOnline,
    },
    config.jwt.jwt_secret as Secret,
    config.jwt.expires_in as string,
  );

  return {
    isNewUser,
    accessToken,
    id: user.id,
    email: user.email,
    role: user.role,
  };
};

const logoutUser = async (id: string) => {
  const userData = await prisma.user.findUnique({
    where: {
      id: id,
    },
  });

  if (!userData) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User not found');
  }

  if (userData.isOnline === false) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User is already logged out');
  }

  await prisma.user.update({
    where: {
      id: id,
    },
    data: {
      isOnline: false,
      fcmToken: null,
    },
  });
  return;
};

export const AuthServices = { loginUserFromDB, socialLogin, logoutUser };
