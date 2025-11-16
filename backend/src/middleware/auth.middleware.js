import jwt from "jsonwebtoken";
import User from "../models/User.js";
import { ENV } from "../lib/env.js";

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt; // check if the token exists
    if (!token)
      return res
        .status(401)
        .json({ message: "Unathorized - No token provided" });

    const decoded = jwt.verify(token, ENV.JWT_SECRET); // check if the token is valid
    if (!decoded)
      return res.status(401).json({ message: "Unathorized - Invalid token" });

    const user = await User.findById(decoded.userId).select("-password"); // check if the user is in our database
    if (!user) return res.status(404).json({ message: "User not found" });

    req.user = user; //
    next(); // user is authenticated 
  } catch (error) {
    console.log("Error in protectRoute middleware: ", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
