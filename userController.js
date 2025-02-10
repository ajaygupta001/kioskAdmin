const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/user.js");
const Workspace = require("../models/workspace.js");
const mongoose = require("mongoose");
const { OAuth2Client } = require("google-auth-library");
const Avatar = require("../models/avatar.js");
const { CustomError } = require("../middlewares/errorHandler.js");
const { uploadFileToBlob } = require("../middlewares/azureBlobService.js");
const nodemailer = require("nodemailer");
// const {
//   verifySocialMediaToken,
// } = require("../middlewares/verifySocialMediaToken.js");

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

const client = new OAuth2Client(GOOGLE_CLIENT_ID);

const JWT_SECRET = process.env.JWT_SECRET || "H491K3P-T5YMG65-JAJAY21-G5KY9NW";
const ADMIN_JWT_SECRET =
  process.env.ADMIN_JWT_SECRET || "AJAYK3P-T5YMAJ75-JAR7G21-HYTEN04W";

//Create Registration
const register = async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      contactNumber,
      loginMode = "email",
      token, // Google token if loginMode is 'google'
    } = req.body;

    // Basic validation for the name and email fields
    if (!name || !email) {
      throw new CustomError("Name and email are required.", 400);
    }

    if (loginMode === "email" && (!password || !contactNumber)) {
      throw new CustomError(
        "Password and contact number are required for email login.",
        400
      );
    } else if (loginMode === "google" && !token) {
      throw new CustomError("Google token is required for Google login.", 400);
    }

    // Handle Google login
    if (loginMode === "google") {
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: GOOGLE_CLIENT_ID,
      });

      const payload = ticket.getPayload();
      const googleEmail = payload.email;
      const userName = payload.name;

      // Check if user already exists
      let user = await User.findOne({ email: googleEmail });

      if (!user) {
        // Create a new user if they don't exist
        user = new User({
          name: userName,
          email: googleEmail,
          loginMode: "google",
        });
        await user.save();
      }

      // Generate JWT token
      const jwtToken = jwt.sign(
        { email: user.email, role: user.role, userid: user._id }, // Payload includes role
        user.role === "admin" ? ADMIN_JWT_SECRET : ADMIN_JWT_SECRET, // Different secret keys
        { expiresIn: "1d" }
      );

      res.cookie("token", jwtToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
      });

      return res.status(200).json({
        success: true,
        message: "Google login successful.",
        token: jwtToken,
        role: user.role,
        loginMode: user.loginMode,
      });
    }

    // Handle email registration
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(404).json({
        success: false,
        message: "A user with this email already exists.",
      });
    }

    // Hash the password for email registration
    let hashedPassword = null;
    if (loginMode === "email") {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      contactNumber,
      loginMode,
    });

    await newUser.save();

    const jwtToken = jwt.sign(
      { email: newUser.email, role: newUser.role },
      JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );

    res.cookie("token", jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    });

    return res.status(201).json({
      success: true,
      message: "User registered successfully.",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        contactNumber: newUser.contactNumber,
        loginMode: newUser.loginMode,
      },
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

//Login User
const login = async (req, res) => {
  try {
    const { email, password, loginMode = "email", token, role } = req.body;
    let user;
    let activeWorkspaces = [];

    if (loginMode === "google") {
      // Verify Google token
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      const googleEmail = payload.email;
      const userName = payload.name;

      // Find or create user
      user = await User.findOne({ email: googleEmail });
      if (!user) {
        user = new User({
          name: userName,
          email: googleEmail,
          loginMode: "google",
          role: "admin",
        });
        await user.save();
      }
    } else {
      // Email login
      user = await User.findOne({ email });
      if (!user) {
        throw new CustomError("User not found", 404);
      }

      if (user.loginMode !== "email") {
        throw new CustomError(`Please use ${user.loginMode} to login.`, 400);
      }

      // Validate password
      const isPasswordCorrect = await bcrypt.compare(password, user.password);
      if (!isPasswordCorrect) {
        return res.status(400).json({ message: "Invalid password" });
      }
    }

    if (role && role !== user.role) {
      console.log(`Changing role from ${user.role} to ${role}`);
      user.role = role;
      await user.save();
    }

    // Retrieve active workspaces for the user
    activeWorkspaces = await Workspace.find({
      user_id: user._id, // Corrected to user._id
      status: "active",
    });

    const workspaceCreated = activeWorkspaces.length > 0;

    // if (!activeWorkspaces.length) {
    //   return res.status(404).json({
    //     message: "No active workspaces found for this user.",
    //   });
    // }

    // Generate JWT token
    // const jwtToken = jwt.sign(
    //   { email: user.email, role: user.role },
    //   JWT_SECRET,
    //   { expiresIn: "1d" }
    // );

    const jwtToken = jwt.sign(
      { email: user.email, role: user.role, userid: user._id }, // Payload includes role
      user.role === "admin" ? ADMIN_JWT_SECRET : ADMIN_JWT_SECRET, // Different secret keys
      { expiresIn: "1d" }
    );

    res.cookie("token", jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    });

    return res.status(200).json({
      success: true,
      message: "Login successful",
      token: jwtToken,
      role: user.role,
      email: user.email,
      loginMode: user.loginMode,
      avatarName: user.activeAvatar,
      avatarVoice: user.activeAvatarVoice,
      gender: user.gender,
      language: user.language,
      userid: user._id,
      //  activeWorkspaces,
      workspaceCreated,
      workspaceMessage: workspaceCreated
        ? "Workspace created"
        : "No active workspace",
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
};

//Check Email Verification
// const checkEmailVerification = async (req, res) => {
//   try {
//     const { email } = req.body;

//     // Check if the email exists in the database
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(404).json({
//         success: false,
//         message: "User with this email does not exist.",
//       });
//     }

//     return res.status(200).json({
//       success: true,
//       message: "User with this email exists.",
//     });
//   } catch (error) {
//     console.error("Error during email verification:", error);
//     return res.status(500).json({
//       success: false,
//       message: "Internal server error.",
//     });
//   }
// };



const checkEmailVerification = async (req, res) => {
  try {
    const { email } = req.body;

    // Check if the email exists in the database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User with this email does not exist.",
      });
    }

    // Generate OTP or Reset Token
    const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    // Create a transporter object
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Reset password link
    const resetLink = `http://localhost:5000/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Reset Password Request",
      text: `Click on this link to reset your password: ${resetLink}`,
    });

    return res.status(200).json({
      success: true,
      message: "Reset password link sent to your email.",
    });
  } catch (error) {
    console.error("Error during email verification:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error.",
    });
  }
};


//Update Reset Password
// const resetPassword = async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) {
//       return res.status(400).json({
//         success: false,
//         message: "Email and new password are required.",
//       });
//     }
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res
//         .status(404)
//         .json({ success: false, message: "User not found." });
//     }

//     const hashedPassword = await bcrypt.hash(password, 10);
//     user.password = hashedPassword;
//     await user.save();

//     return res.status(200).json({
//       success: true,
//       message:
//         "Password reset successful. You can now log in with your new password.",
//     });
//   } catch (error) {
//     return res.status(500).json({ success: false, message: error.message });
//   }
// };



const resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({
        success: false,
        message: "Token and new password are required.",
      });
    }

    // Verify Token (handle expiration)
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(400).json({ success: false, message: "Token has expired. Request a new reset link." });
      }
      return res.status(400).json({ success: false, message: "Invalid token." });
    }

    // Check if user exists
    const user = await User.findOne({ email: decoded.email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({
      success: true,
      message: "Password reset successful. You can now log in with your new password.",
    });
  } catch (error) {
    console.error("Reset Password Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
};



// const confirmPasswordReset = async (req, res) => {
//   try {
//     const { oldPassword, newPassword } = req.body;
//     const userId = req.user.id; 

//     if (!userId) {
//       console.log("User ID is missing");
//       return res.status(404).json({
//         message: "Unauthorized: User ID missing.",
//       });
//     }

//     const user = await User.findById(userId);
//     if (!user) {
//       return res.status(404).json({ message: "User not found" });
//     }

//     const isMatch = await bcrypt.compare(oldPassword, user.password);
//     if (!isMatch) {
//       return res.status(400).json({ message: "Old password is incorrect" });
//     }

//     const hashedNewPassword = await bcrypt.hash(newPassword, 10);

//     user.password = hashedNewPassword;
//     await user.save();

//     return res.status(200).json({ message: "Password updated successfully" });
//   } catch (error) {
//     console.error("Error in password reset:", error);
//     return res.status(500).json({ message: "Internal server error" });
//   }
// };



const confirmPasswordReset = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id; // Extracted from verifyToken middleware

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized: User ID missing." });
    }

    // 🔹 Find user in DB
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // 🔹 Compare old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Old password is incorrect" });
    }

    // 🔹 Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword;
    await user.save();

    return res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("Error in password reset:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};



//Get All User
const getAllUsers = async (req, res) => {
  try {
    const users = await User.find({});
    if (!users.length) {
      throw new CustomError("No users found", 404);
    }
    return res.status(200).json({ success: true, users });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

// Get User by ID
const getUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id);
    if (!user) {
      throw new CustomError("User not found", 404);
    }
    // return res.status(200).json({ success: true, user });
    return res
      .status(200)
      .json({ success: true, user, avatarName: user.activeAvatar });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

// Delete User
const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByIdAndDelete(id);
    if (!user) {
      throw new CustomError("User not found", 404);
    }
    await user.deleteOne();
    return res
      .status(200)
      .json({ success: true, message: "User deleted successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

//For User Name and ProductImage
const updateUserAndProductImage = async (req, res) => {
  try {
    const user_id = req.user.id;
    const { name, product_image } = req.body;

    if (!name && !product_image) {
      return res.status(400).json({
        success: false,
        message: "Please provide a name or product_image to update.",
      });
    }

    if (name) {
      const user = await User.findOneAndUpdate(
        { _id: user_id },
        { $set: { name } },
        { new: true }
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found.",
        });
      }
    }
    if (product_image) {
      const workspace = await Workspace.findOneAndUpdate(
        { user_id, status: "active" },
        { $set: { product_image } },
        { new: true }
      );

      if (!workspace) {
        return res.status(404).json({
          success: false,
          message: "Active workspace not found for the user.",
        });
      }
    }

    res.status(200).json({
      success: true,
      message: "User name and/or product image updated successfully.",
    });
  } catch (error) {
    console.error("Error updating name and product image:", error);
    return res.status(500).json({
      success: false,
      error: "An error occurred while updating name and product image.",
    });
  }
};

//Get User Name, Email ,Language, gender, and ProductImage URl
const getUserEmail = async (req, res) => {
  try {
    const user_id = req.user.id;
    // console.log("Verified Token:", req.user);

    const user = await User.findOne({ _id: user_id }).select(
      "name email profileImage language gender"
    );
    if (!user) {
      throw new CustomError("User not found", 400);
    }

    res.status(200).json({
      success: true,
      message: "User retrieved successfully.",
      userName: user.name,
      userEmail: user.email,
      gender: user.gender,
      language: user.language,
      profileImage: user.profileImage,
    });
  } catch (error) {
    console.error("Error fetching active workspaces:", error);
    return res.status(500).json({
      error: "An error occurred while fetching active workspaces.",
    });
  }
};

//Update User Profile
const updateUserProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    const { userName, gender, language } = req.body;
    const file = req.file;

    const user = await User.findById(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    let profileImageUrl = user.profileImage;
    if (file) {
      const uploadedFile = await uploadFileToBlob(file);
      profileImageUrl = uploadedFile.url;
    }

    user.gender = gender || user.gender;
    user.language = language || user.language;
    user.name = userName || user.name;
    user.profileImage = profileImageUrl;

    await user.save();

    res.status(200).json({
      success: true,
      message: "User profile updated successfully",
      userName: user.name,
      profileImage: user.profileImage,
      gender: user.gender,
      language: user.language,
    });
  } catch (error) {
    console.error("Error updating user profile:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};

module.exports = {
  register,
  login,
  getAllUsers,
  getUser,
  deleteUser,
  resetPassword,
  checkEmailVerification,
  updateUserAndProductImage,
  getUserEmail,
  updateUserProfile,
  confirmPasswordReset,
};
