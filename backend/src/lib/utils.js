import jwt from "jsonwebtoken";

export const generateToken = (userId, res) => {
  // create a token for the user
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("jwt", token, {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7d in MS
    httpOnly: true, // prevent XSS attacks: cross-site scripting
    sameSite: "strict", // CSRF attacks
    secure: process.env.NODE_ENV === "development" ? false : true,
  });

  return token;
};

// http://localhost
// https://somedomain.com - s stands for secure
