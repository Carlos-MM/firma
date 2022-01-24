const dbContext = require('../database/context');

function json(status,message,data){
    return {
        status: status,
        message : message,
        data : data
     }
}

exports.login=(req,res)=>
{
    return res.json(json(true, "Login", 'Usuario logeado'));
}

  
  
  
  