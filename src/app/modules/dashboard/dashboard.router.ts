import express from 'express';
import auth from '../../middlewares/auth';
import { UserRole } from '@prisma/client';
import { DashboardControllers } from './dashboard.controller';

const router = express.Router();

router.post(
  '/create-admin',
  auth(UserRole.SUPER_ADMIN),
  DashboardControllers.createAdmin,
);

router.delete(
  '/delete-admin/:id',
  auth(UserRole.SUPER_ADMIN),
  DashboardControllers.deleteAdmin,
);

router.get(
  '/get-all-users',
  auth(UserRole.SUPER_ADMIN, UserRole.ADMIN),
  DashboardControllers.getAllUsers,
);

router.get(
  '/get-user/:id',
  auth(UserRole.SUPER_ADMIN, UserRole.ADMIN),
  DashboardControllers.getUserById,
);

router.delete(
  '/delete-user/:id',
  auth(UserRole.SUPER_ADMIN, UserRole.ADMIN),
  DashboardControllers.deleteUser,
);

export const AdminRouters = router;
