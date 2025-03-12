import ApiError from '../../errors/ApiError';
import prisma from '../../helpers/prisma';
import httpStatus from 'http-status';
import * as bcrypt from 'bcrypt';
import { IPaginationOptions } from '../../interfaces/paginations';
import { calculatePagination } from '../../utils/calculatePagination';
import { Prisma } from '@prisma/client';

export interface Filters {
  search?: string;
  username?: string;
  email?: string;
}

const createAdmin = async (payload: {
  name: string;
  email: string;
  password: string;
  phoneNumber?: string;
}) => {
  const existingUser = await prisma.user.findUnique({
    where: {
      email: payload.email,
    },
  });

  if (existingUser) {
    throw new ApiError(
      httpStatus.CONFLICT,
      'User already exists with this email',
    );
  }

  const hashedPassword: string = await bcrypt.hash(payload.password, 12);

  const createAdmin = await prisma.user.create({
    data: {
      name: payload.name,
      email: payload.email,
      password: hashedPassword,
      role: 'ADMIN',
      isVerified: true,
      phoneNumber: payload.phoneNumber,
    },
  });

  const filteredAdmin = Object.fromEntries(
    Object.entries(createAdmin).filter(([_, value]) => value !== null),
  );

  return filteredAdmin;
};

const deleteAdmin = async (adminId: string) => {
  const existingAdmin = await prisma.user.findUnique({
    where: {
      id: adminId,
    },
  });

  if (!existingAdmin) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Admin not found');
  }
  const deleteAdmin = await prisma.user.delete({
    where: {
      id: adminId,
    },
  });

  return deleteAdmin;
};

const getAllUsers = async (
  paginationOptions: IPaginationOptions,
  params: Filters,
) => {
  const { page, limit, skip, sortBy, sortOrder } =
    calculatePagination(paginationOptions);
  const { search, username, email } = params;

  const whereConditions: Prisma.UserWhereInput = {};

  if (search) {
    whereConditions.OR = [
      { username: { contains: search, mode: 'insensitive' } },
      { email: { contains: search, mode: 'insensitive' } },
    ];
  }

  if (username) {
    whereConditions.username = { contains: username, mode: 'insensitive' };
  }

  if (email) {
    whereConditions.email = { contains: email, mode: 'insensitive' };
  }

  if (Object.keys(whereConditions).length === 0) {
    delete whereConditions.OR;
  }

  const [users, total] = await prisma.$transaction([
    prisma.user.findMany({
      where: whereConditions,
      select: {
        id: true,
        name: true,
        email: true,
        username: true,
        profileImage: true,
        role: true,
        phoneNumber: true,
        status: true,
      },
      skip,
      take: limit,
      orderBy: {
        [sortBy]: sortOrder,
      },
    }),
    prisma.user.count({
      where: whereConditions,
    }),
  ]);

  const meta = {
    page,
    limit,
    total_docs: total,
    total_pages: Math.ceil(total / limit),
  };

  return {
    meta,
    data: users,
  };
};

const getUserById = async (userId: string) => {
  const result = await prisma.user.findUnique({
    where: {
      id: userId,
    },
    select: {
      id: true,
      name: true,
      email: true,
      username: true,
      phoneNumber: true,
      profileImage: true,
    },
  });
  if (!result) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  return result;
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
  return null;
};

export const DashboardServices = {
  createAdmin,
  deleteAdmin,
  getAllUsers,
  getUserById,
  deleteUser,
};
