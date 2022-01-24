const express=require('express');
const router=express.Router();
const signature = require('../controllers/signatureController');
const checkAuth=require('../middleware/check-auth');

router.get('/getSignatureLoggedIn',checkAuth,signature.getSignatureLoggedIn);
router.post('/getSignature',signature.getSignature);
router.post('/getInfoSignature',signature.getInfoSignature);
//router.get('/getInfoSignature/:filename',signature.getInfoSignature);
module.exports=router;

