import httpStatus from 'http-status';
import { AuthServices } from './auth.service';
import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';

const loginUser = catchAsync(async (req, res) => {
  const { email, password, fcmToken } = req.body;
  const result = await AuthServices.loginUserFromDB({
    email,
    password,
    fcmToken,
  });
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'User successfully logged in',
    data: result,
  });
});

const socialLogin = catchAsync(async (req, res) => {
  const { email, role, name, fcmToken } = req.body;
  const result = await AuthServices.socialLogin({
    email,
    role,
    name,
    fcmToken,
  });

  const statusCode = result.isNewUser ? httpStatus.CREATED : httpStatus.OK;
  const message = result.isNewUser
    ? 'User successfully created'
    : 'User successfully logged in';

  sendResponse(res, {
    statusCode,
    success: true,
    message,
    data: result,
  });
});

const logoutUser = catchAsync(async (req, res) => {
  const id = req.user.id;
  await AuthServices.logoutUser(id);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'User Successfully logged out',
    data: null,
  });
});

export const AuthControllers = { loginUser, logoutUser, socialLogin };
