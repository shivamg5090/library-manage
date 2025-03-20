import express from "express";
import User from "../models/User.js";
import bcrypt from "bcrypt";

const router = express.Router();

/* ------------------ User Registration ------------------ */
router.post("/register", async (req, res) => {
  try {
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPass = await bcrypt.hash(req.body.password, salt);

    // Create a new user object
    const newUser = new User({
      userType: req.body.userType,
      userFullName: req.body.userFullName,
      admissionId: req.body.admissionId,
      employeeId: req.body.employeeId,
      age: req.body.age,
      dob: req.body.dob,
      gender: req.body.gender,
      address: req.body.address,
      mobileNumber: req.body.mobileNumber,
      email: req.body.email,
      password: hashedPass,
      isAdmin: req.body.isAdmin,
    });

    // Save the user to the database
    const savedUser = await newUser.save();

    // Return user data without password
    const { password, ...otherDetails } = savedUser._doc;
    res.status(201).json(otherDetails);
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json("Internal Server Error");
  }
});

/* ------------------ User Login ------------------ */
router.post("/signin", async (req, res) => {
  try {
    // Find user by Admission ID or Employee ID
    const user = req.body.admissionId
      ? await User.findOne({ admissionId: req.body.admissionId })
      : await User.findOne({ employeeId: req.body.employeeId });

    // If user not found
    if (!user) {
      return res.status(404).json("User not found");
    }

    // Compare entered password with hashed password
    const validPass = await bcrypt.compare(req.body.password, user.password);
    if (!validPass) {
      return res.status(400).json("Wrong Password");
    }

    // Send user data without password
    const { password, ...otherDetails } = user._doc;
    res.status(200).json(otherDetails);
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json("Internal Server Error");
  }
});

export default router;
