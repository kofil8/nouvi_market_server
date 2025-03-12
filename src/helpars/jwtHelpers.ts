import jwt, { Secret, SignOptions, JwtPayload } from 'jsonwebtoken';

// Function to generate a JWT
const generateToken = (
  payload: Record<string, unknown>,
  secret: Secret,
  expiresIn: string,
): string => {
  const token = jwt.sign(payload, secret, {
    algorithm: 'HS256',
    expiresIn,
  } as SignOptions);

  return token;
};

// Function to verify a JWT
const verifyToken = (token: string, secret: Secret): JwtPayload | string => {
  try {
    const decoded = jwt.verify(token, secret);
    return decoded;
  } catch (error) {
    throw new Error('Token verification failed');
  }
};

export const jwtHelpers = {
  generateToken,
  verifyToken,
};
