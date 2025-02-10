const User = require("../models/user");

const verifyEmail = async (req, res, next) => {
  try {
    const { email } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User with this email does not exist.",
      });
    }

    // Check if email is verified
    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        message: "Email not verified. Please verify your email first.",
      });
    }

    next(); // Allow request to proceed if email is verified
  } catch (error) {
    console.error("Email verification middleware error:", error);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
};

module.exports = verifyEmail;
