import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';
import httpStatus from 'http-status';
import { DashboardServices } from './dashboard.service';
import { pick } from '../../../helpars/pick';

const createAdmin = catchAsync(async (req, res) => {
  const { name, email, password, phoneNumber } = req.body;
  const result = await DashboardServices.createAdmin({
    name,
    email,
    password,
    phoneNumber,
  });

  sendResponse(res, {
    statusCode: httpStatus.CREATED,
    message: 'Admin created successfully',
    data: result,
  });
});

const deleteAdmin = catchAsync(async (req, res) => {
  const adminId = req.params.id;
  const result = await DashboardServices.deleteAdmin(adminId);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'Admin deleted successfully',
    data: result,
  });
});

const getAllUsers = catchAsync(async (req, res) => {
  const paginationOptions = pick(req.query, [
    'page',
    'limit',
    'sortBy',
    'sortOrder',
  ]);

  const page = parseInt(paginationOptions.page as string, 10) || 1;
  const limit = parseInt(paginationOptions.limit as string, 10) || 10;
  const skip = (page - 1) * limit;

  paginationOptions.page = page;
  paginationOptions.limit = limit;
  paginationOptions.skip = skip;

  const filters = pick(req.query, ['search', 'username', 'email']);
  const result = await DashboardServices.getAllUsers(
    paginationOptions,
    filters,
  );
  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'Users Retrieve successfully',
    data: result,
  });
});

const getUserById = catchAsync(async (req, res) => {
  const userId = req.params.id;
  const result = await DashboardServices.getUserById(userId);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'User details retrieved successfully',
    data: result,
  });
});

const deleteUser = catchAsync(async (req, res) => {
  const id = req.user.id;
  const result = await DashboardServices.deleteUser(id);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    message: 'User deleted successfully',
    data: result,
  });
});

export const DashboardControllers = {
  createAdmin,
  deleteAdmin,
  getAllUsers,
  getUserById,
  deleteUser,
};
