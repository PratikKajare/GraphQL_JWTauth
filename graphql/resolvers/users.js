const User = require('../../models/User');
const { ApolloError } = require('apollo-server-errors');
const bcrypt=require("bcryptjs")
const jwt = require("jsonwebtoken");


module.exports = {
    Mutation: {
        async registerUser(_parent, { registerInput: { username, email,password } }) {
            //see if an old user exists with email attempting to register
            const oldUser = await User.findOne({ email });
            if (oldUser) {
                throw new ApolloError("A USER IS ALREADY REGISTERED WITH THE EMAIL"+ email, "USER_ALREADY_EXISTS")
            }
            // Encrypt password
            var encryptedPassword = await bcrypt.hash(password, 10)
            
            //Build out mongoose model (User)
            const newUser = new User({
                username: username,
                email: email.toLowerCase(),
                password: encryptedPassword
            })

            //create our jwt
            const token = jwt.sign(
                { user_id: newUser._id, email },
                "UNSAFE_STRING",
                {
                    expiresIn: "2h"
                }
            );
            newUser.token = token; 
            //save our user in mongodb
            const res = await newUser.save();
            return {
                id: res.id,
                ...res._doc
            }
        },
        async loginUser(_, { loginInput: { email, password } }) {
            // see if a user exist with the email
            const user = await User.findOne({ email });
            //check if the entered password equals the encrypted
            if (user && (await bcrypt.compare(password,user.password))) {
                //Create a new TOKEN
                const token = jwt.sign(
                    { user_id: user._id, email },
                    "UNSAFE_STRING",
                    {
                        expiresIn: "4h"
                    }
                );
                //attach token to user model that we found above
                user.token = token;
                return {
                    id: user.id,
                ...user._doc
                }   
            } else {
                //if user does't exist ,return error
                throw new ApolloError('Incorrect password', 'INCORRECT_PASSWORD');  
            }
        }
    },
    Query: {
        user: (_, {ID}) => User.findById(ID)
    }
}