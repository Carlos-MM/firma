
const jwt=require('jsonwebtoken');
const config=require('../config/config');

module.exports=(req,res,next)=>{
    try{
        const decoded=jwt.verify(req.body.token,config.JWT_KEY);        
        req.userData=decoded;
        next();
    }
    catch(error)
    {
        return res.status(401).json({
            message:error.message
        });

    }

};