import { emailTemplate } from '../../helpars/emailtempForOTP';
import sentEmailUtility from './sentEmailUtility';

export const generateOtpReg = async (payload: { email: string }) => {
  // Generate OTP
  const otp = Math.floor(100000 + Math.random() * 9000);

  const emailSubject = 'OTP Verification for Registration';

  const emailText = `Your OTP is: ${otp}`;

  const textForRegistration = `Thank you for registering with Nouvi.. To complete your registration, please verify your email address by entering the verification code below.`;

  const emailHTML = emailTemplate(otp, textForRegistration);

  await sentEmailUtility(payload.email, emailSubject, emailText, emailHTML);

  const otpExpiry = new Date();
  otpExpiry.setMinutes(otpExpiry.getMinutes() + 2);

  return {
    otp,
    otpExpiry,
  };
};
