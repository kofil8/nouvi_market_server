import * as bcrypt from 'bcrypt';
import httpStatus from 'http-status';
import { Secret } from 'jsonwebtoken';
import { jwtHelpers } from '../../../helpars/jwtHelpers';
import ApiError from '../../errors/ApiError';
import prisma from '../../helpers/prisma';
import { generateTokenReset } from '../../utils/generateTokenForReset';
import { generateOtpReg } from '../../utils/otpGenerateReg';
import { generateOtp } from '../../utils/otpGenerateResetP';
import config from '../../../config';
import { stripe } from '../../utils/stripe';
import { generateToken } from '../../utils/generateToken';

interface VerifyOtpPayload {
  email: string;
  otp: number;
  fcmToken?: string;
}

const registerUserIntoDB = async (
  file: Express.Multer.File | undefined,
  payload: any,
) => {
  const parsedPayload =
    typeof payload === 'string' ? JSON.parse(payload) : payload;

  const existingUser = await prisma.user.findUnique({
    where: { email: parsedPayload.email },
  });

  if (existingUser) {
    throw new ApiError(
      httpStatus.CONFLICT,
      'User already exists with this email',
    );
  }

  const profileImage = file?.originalname
    ? `${config.backend_image_url}/uploads/profile/${file.originalname}`
    : '';

  const [hashedPassword, stripeCustomer] = await Promise.all([
    bcrypt.hash(parsedPayload.password, 12),
    stripe.customers.create({
      email: parsedPayload.email,
      name: parsedPayload.name,
      phone: parsedPayload.phoneNumber,
    }),
  ]);

  const { otp, otpExpiry } = await generateOtpReg({
    email: parsedPayload.email,
  });

  const user = await prisma.$transaction(async (prisma) => {
    const newUser = await prisma.user.create({
      data: {
        name: parsedPayload.name,
        email: parsedPayload.email,
        password: hashedPassword,
        profileImage,
        role: parsedPayload.role,
        isVerified: false,
        phoneNumber: parsedPayload.phoneNumber,
        stripeCustomerId: stripeCustomer.id,
      },
    });

    await prisma.otp.create({
      data: {
        email: parsedPayload.email,
        otp,
        expiry: otpExpiry,
      },
    });

    return newUser;
  });

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    isVerified: user.isVerified,
  };
};

const checkUserName = async (username: string) => {
  const user = await prisma.user.findUnique({
    where: {
      username,
    },
  });

  if (user) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User name already exists');
  }

  return null;
};

const resendOtpReg = async (payload: { email: string }) => {
  const userData = await prisma.user.findUnique({
    where: {
      email: payload.email,
    },
  });

  if (!userData) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User not found');
  }

  const { otp, otpExpiry } = await generateOtpReg({ email: payload.email });

  // Find otp in database
  const otpData = await prisma.otp.findFirst({
    where: {
      id: userData.id,
    },
  });

  if (!otpData) {
    await prisma.otp.create({
      data: {
        email: payload.email,
        otp,
        expiry: otpExpiry,
      },
    });
  } else {
    await prisma.otp.update({
      where: {
        id: userData.id,
      },
      data: {
        otp,
        expiry: otpExpiry,
      },
    });
  }

  return { otpExpiry };
};

const verifyOtp = async (payload: VerifyOtpPayload) => {
  const { email, otp, fcmToken } = payload;

  const [userData, otpData] = await Promise.all([
    prisma.user.findUnique({ where: { email } }),
    prisma.otp.findFirst({ where: { email, otp } }),
  ]);

  if (!userData) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User not found');
  }

  if (!otpData) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Invalid OTP');
  }

  if (otpData.expiry < new Date()) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'OTP has expired');
  }

  const updatedUser = await prisma.$transaction(async (tx) => {
    await tx.otp.delete({ where: { id: otpData.id } });

    if (fcmToken) {
      await tx.user.update({
        where: { email },
        data: { fcmToken },
      });
    }

    return tx.user.update({
      where: { email },
      data: { isVerified: true, isOnline: true },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isVerified: true,
      },
    });
  });

  // Generate an access token for the user
  const accessToken = generateToken(
    {
      id: updatedUser.id,
      email: updatedUser.email,
      role: updatedUser.role,
      isOnline: true,
    },
    config.jwt.jwt_secret as Secret,
    config.jwt.expires_in as string,
  );

  return {
    accessToken,
    id: updatedUser.id,
    email: updatedUser.email,
    name: updatedUser.name,
    role: updatedUser.role,
    isVerified: updatedUser.isVerified,
  };
};

const getAllUsersFromDB = async () => {
  const result = await prisma.user.findMany({
    where: {
      isVerified: true,
    },
  });

  const filtered = result.map((user) => {
    const { password, ...rest } = user;
    return Object.fromEntries(
      Object.entries(rest).filter(([_, value]) => value !== null),
    );
  });

  return filtered;
};

const getUserDetailsFromDB = async (id: string) => {
  const user = await prisma.user.findUnique({
    where: {
      id,
    },
  });
  if (!user) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User not found');
  }

  const { password, ...rest } = user;

  const filteredProfile = Object.fromEntries(
    Object.entries(rest).filter(([_, value]) => value !== null),
  );
  return filteredProfile;
};

const deleteUser = async (id: string) => {
  const existingUser = await prisma.user.findUnique({
    where: { id },
  });

  if (!existingUser) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User not found');
  }
  const result = await prisma.user.delete({
    where: {
      id: id,
    },
  });
  return;
};

const forgotPassword = async (payload: { email: string }) => {
  const { otp, otpExpiry } = await generateOtp(payload);

  // Check if OTP already exists for the user
  const existingOtp = await prisma.otp.findFirst({
    where: { email: payload.email },
  });

  if (existingOtp) {
    await prisma.otp.update({
      where: {
        id: existingOtp.id,
      },
      data: {
        otp,
        expiry: otpExpiry,
      },
    });
  } else {
    await prisma.otp.create({
      data: {
        email: payload.email,
        otp,
        expiry: otpExpiry,
      },
    });
  }
};

const resendOtpRest = async (payload: { email: string }) => {
  const { otp, otpExpiry } = await generateOtp(payload);

  // Check if OTP already exists for the user
  const existingOtp = await prisma.otp.findFirst({
    where: { email: payload.email },
  });

  if (existingOtp) {
    await prisma.otp.update({
      where: {
        id: existingOtp.id,
      },
      data: {
        otp,
        expiry: otpExpiry,
      },
    });
  } else {
    await prisma.otp.create({
      data: {
        email: payload.email,
        otp,
        expiry: otpExpiry,
      },
    });
  }

  return { otpExpiry };
};

const verifyResetOtp = async (payload: { email: string; otp: number }) => {
  const userData = await prisma.user.findUnique({
    where: {
      email: payload.email,
    },
  });

  if (!userData) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User not found');
  }

  const otpData = await prisma.otp.findFirst({
    where: {
      email: payload.email,
    },
  });

  if (otpData?.otp !== payload.otp) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Invalid OTP');
  }

  if (otpData?.expiry < new Date()) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'OTP has expired');
  }

  await prisma.otp.delete({
    where: {
      id: otpData.id,
    },
  });

  const accessToken = generateTokenReset(
    {
      id: userData.id,
      email: userData.email,
      isVerified: userData.isVerified,
    },
    config.jwt.jwt_secret as Secret,
    config.jwt.expires_in as string,
  );

  return {
    message: 'OTP verified successfully for reset password',
    accessToken,
  };
};

const resetPassword = async (
  accessToken: string,
  payload: { password: string },
) => {
  if (!accessToken) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'You are not authorized!');
  }

  const decodedToken = jwtHelpers.verifyToken(
    accessToken,
    config.jwt.jwt_secret as Secret,
  );

  const email = decodedToken?.email;

  if (!email) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'You are not authorized!');
  }

  const userData = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!userData) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User not found');
  }

  const hashedPassword: string = await bcrypt.hash(payload.password, 12);

  await prisma.user.update({
    where: {
      email,
    },
    data: {
      password: hashedPassword,
    },
  });

  return;
};

const changePassword = async (userId: string, payload: any) => {
  if (!payload.oldPassword || !payload.newPassword) {
    throw new ApiError(
      httpStatus.BAD_REQUEST,
      'Both old and new passwords are required',
    );
  }
  const userData = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!userData) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }

  const isPasswordCorrect = await bcrypt.compare(
    payload.oldPassword,
    userData.password,
  );
  if (!isPasswordCorrect) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Invalid old password');
  }

  if (payload.oldPassword === payload.newPassword) {
    throw new ApiError(
      httpStatus.BAD_REQUEST,
      'New password should be different from old password',
    );
  }

  const hashedPassword = await bcrypt.hash(payload.newPassword, 12);

  await prisma.user.update({
    where: { id: userId },
    data: { password: hashedPassword },
  });

  return;
};

const updateLocation = async (
  userId: string,
  longitude: number,
  latitude: number,
) => {
  const result = await prisma.user.update({
    where: { id: userId },
    data: {
      latitude,
      longitude,
    },
  });

  return result;
};

export const UserServices = {
  registerUserIntoDB,
  checkUserName,
  resendOtpReg,
  getAllUsersFromDB,
  getUserDetailsFromDB,
  deleteUser,
  forgotPassword,
  resendOtpRest,
  resetPassword,
  verifyResetOtp,
  verifyOtp,
  changePassword,
  updateLocation,
};
