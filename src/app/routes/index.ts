import express from 'express';
import { UserRouters } from '../modules/user/user.router';
import { AuthRouters } from '../modules/auth/auth.router';
import { ProfileRouters } from '../modules/profile/profile.router';
import { AdminRouters } from '../modules/dashboard/dashboard.router';

const router = express.Router();

const moduleRoutes = [
  {
    path: '/dashboard',
    route: AdminRouters,
  },
  {
    path: '/auth',
    route: AuthRouters,
  },
  {
    path: '/users',
    route: UserRouters,
  },
  {
    path: '/profile',
    route: ProfileRouters,
  },
];

moduleRoutes.forEach((route) => router.use(route.path, route.route));

export default router;
