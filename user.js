const mongoose = require("mongoose");
const validator = require("validator");

const userSchema = new mongoose.Schema(
  {
    // _id: {
    //     type: String,
    //     required: [true, "Please enter ID"],
    // },
    name: {
      type: String,
      required: [true, "Please enter Name"],
    },
    email: {
      type: String,
      unique: [true, "Email already exists"],
      required: [true, "Please enter Email"],
      validate: [validator.isEmail, "Please enter a valid email"],
    },
    contactNumber: {
      type: String,
      //required: [true, "Please enter contact number"],
      validate: {
        validator: function (v) {
          return /\d{10}/.test(v); // Example validation for a 10-digit number
        },
        message: "Please enter a valid contact number",
      },
      required: function () {
        return this.loginMode === "email";
      },
    },
    password: {
      type: String,
      required: function () {
        return this.loginMode === "email";
      },
      // validate: {
      //   validator: function (v) {
      //     // Regex
      //     return /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
      //   },
      //   message:
      //     "Password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one number, and one special character.",
      // },
    },
    

    role: {
      type: String,
      enum: ["admin", "user"],
      required: [true, "Please enter role"],
      default: "admin",
    },

    loginMode: {
      type: String,
      enum: ["email", "google", "facebook", "twitter"],
      default: "email",
    },
    activeAvatar: {
      type: String,
      default: null,
    },

    activeAvatarVoice: {
      type: String,
      default: null,
    },
    gender: {
      type: String,
      enum: ["male", "female", "other"],
      required: false, 
      default: null,
    },
    language: {
      type: String,
      required: false,
      default: "en", 
    },

    emailVerified: {
      type: Boolean,
      default: false
    },
    verificationToken: {
      type: String,
      default: null
    },
    resetPasswordToken: {
      type: String,
      default: null
    },
    resetPasswordExpires: {
      type: Date,
      default: null
    },
    
    //  activeAvatar: { type: mongoose.Schema.Types.ObjectId, ref: 'Avatar', default: null },
    workspace_id: { type: Number, required: false },
    workspace_slug: { type: String, required: false },
    profileImage: { type: String, default: null },
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model("User", userSchema);
module.exports = User;



