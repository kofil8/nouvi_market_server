import { Request, Response } from 'express';
import httpStatus from 'http-status';
import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';
import { UserServices } from './user.service';

const registerUser = catchAsync(async (req: Request, res: Response) => {
  const file = req.file;
  const payload = req.body.bodyData;

  const result = await UserServices.registerUserIntoDB(file, payload);

  sendResponse(res, {
    statusCode: httpStatus.CREATED,
    message: 'Thanks for registering with us, please verify your email',
    data: result,
  });
});

const checkuserName = catchAsync(async (req: Request, res: Response) => {
  const { username } = req.query;
  const result = await UserServices.checkUserName(username as string);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'User name check successfully',
    data: result,
  });
});

const resendOtpReg = catchAsync(async (req: Request, res: Response) => {
  const payload = req.body;
  const result = await UserServices.resendOtpReg(payload);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'OTP Resend successfully, please check your email',
    data: result,
  });
});

const forgotPassword = catchAsync(async (req: Request, res: Response) => {
  const result = await UserServices.forgotPassword(req.body);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'OTP sent successfully, please check your email',
    data: result,
  });
});

const resendOtpRest = catchAsync(async (req: Request, res: Response) => {
  const payload = req.body;
  const result = await UserServices.resendOtpRest(payload);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'OTP Resend successfully, please check your email',
    data: result,
  });
});

const verifyOtp = catchAsync(async (req: Request, res: Response) => {
  const { email, otp, fcmToken } = req.body;
  const result = await UserServices.verifyOtp({ email, otp, fcmToken });

  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'OTP verified successfully, welcome to our app',
    data: result,
  });
});

const ResetOtpVerify = catchAsync(async (req: Request, res: Response) => {
  const email = req.body.email;
  const otp = req.body.otp;
  const result = await UserServices.verifyResetOtp({ email, otp });

  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'OTP verified successfully for reset password',
    data: result,
  });
});

const resetPassword = catchAsync(async (req: Request, res: Response) => {
  const { password } = req.body;
  const userId = req.user.id;
  const result = await UserServices.resetPassword(userId, password);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'Password reset successfully',
    data: result,
  });
});

const changePassword = catchAsync(async (req: Request, res: Response) => {
  const payload = req.body;
  const userId = req.user.id;
  const result = await UserServices.changePassword(userId, payload);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'Password changed successfully',
    data: result,
  });
});

const updateLocation = catchAsync(async (req: Request, res: Response) => {
  const userId = req.user.id;
  const { longitude, latitude } = req.body;
  const result = await UserServices.updateLocation(userId, longitude, latitude);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'Location updated successfully',
    data: result,
  });
});

export const UserControllers = {
  registerUser,
  checkuserName,
  resendOtpReg,
  forgotPassword,
  resendOtpRest,
  ResetOtpVerify,
  resetPassword,
  verifyOtp,
  changePassword,
  updateLocation,
};
