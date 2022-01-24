const express=require('express');
const router=express.Router();
const users = require('../controllers/usersController');


router.get('/login',users.login);

module.exports=router;

