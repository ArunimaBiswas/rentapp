const router = require('express').Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const User = require('../models/User');

// multer config	
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, "public/uploads/");
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    },
});

const upload = multer({ storage });




// USER REGISTER
router.post("/register", upload.single('profileImage'), async (req, res) => {
    try{
        // tale all info

        const{ firstName, lastName, email, password } = req.body;
        // the uploaded img file
        const profileImage = req.file;

        if(!profileImage){
            return res.status(400).send("No file uploaded");
        }

        //  path to the image

        const profileImagePath = profileImage.path;
        // /if user exists

        const existingUser = await User.findOne({ email })
        if(existingUser){
            return res.status(409).json({ message: "User already exists"});
        }
        // hash the password
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);

        // create a new user
        const newUser = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            profileImagePath,
        });

        // save the user

        await newUser.save();

        // send a message
        res.status(200).json({ message: "User registered successfully", user: newUser});
    }catch(err){
        console.log(err);
        res.status(500).json({ message: "Registration failed", error: err.message});
    }   
})

// USER LOGIN
router.post("/login", async (req, res) => {
    try{
        // take all info
        const { email, password } = req.body;

        // check if user exists
        const user = await User.findOne({ email })
        if(!user){
            return res.status(409).json({ message: "User does not exist"});
        }

        // check if password is correct

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch){
            return res.status(400).json({ message: "Invalid credentials"});
        }

        // create a token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        delete user.password;

        res.status(200).json({ token, user});

    }catch(err){
        console.log(err);
        return res.status(400).json({ error: err.message});
    }
    })

module.exports = router;
