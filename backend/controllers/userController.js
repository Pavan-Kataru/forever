import validator from 'validator'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import userModel from '../models/userModel.js'


const createToken = (id) => {
    return jwt.sign({id},process.env.JWT_SECRET)
}

//Route for user login

const loginUser =  async  (req,res)=>{

    try{
        const {email, password} = req.body;

        const user = await userModel.findOne({email});

        if (!user){
            return res.json({success:false, message:"User Doesn't exists"})
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {

            const token = createToken(user._id)
            res.json({success:true, token})
        }else{
            return res.json({success:false, message:"Invalid credentials"})
        }

    }catch(error){
        console.log(error);
        res.json({success:false, message: error.message})
    }

}


// Route for  user Register

const registerUser = async (req, res)=>{

    try{
        const {name, email, password} = req.body

        //checking use already existed or not
        /* here below we used awit (const exists = await userModel.findOne({email});)
        if we doesn't use await here then if i enter new user registration details it will return 
        'user already exists', coz we aren't waiting for the result of the asychronous operation */
        const exists = await userModel.findOne({email}); 
        if (exists){
            return res.json({success: false, message:'User already exists'})
        }

        // validating email format & strong password
        if(!validator.isEmail(email)){
            return res.json({success:false, message:"Please enter a valid email"})
        }
        if(password.length < 8){
            return res.json({success:false, message:"please enter a strong password"})
        }

        // hashing user password
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password,salt)
        
        const newUser = new userModel({
            name,
            email,
            password: hashedPassword
        })

        const user = await newUser.save()

        const token = createToken(user._id)

        res.json({success:true, token})

    }catch(error){
        console.log(error);
        res.json({success:false, message: error.message})

    }

}

// Route for admin login

const adminLogin = async (req, res)=>{
    try{

        const {email, password} = req.body

        if(email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD){
            const token = jwt.sign(email+password, process.env.JWT_SECRET)
            res.json({success:true, token})
        } else{
            res.json({success:false, message:"Invalid credentials"})
        }

    }catch{
        console.log(error);
        res.json({success:false, message: error.message})
    }

}

export {loginUser, registerUser, adminLogin}