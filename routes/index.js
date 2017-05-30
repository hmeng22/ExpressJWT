var express = require('express');
var router = express.Router();

var sysController = require('../controller/sysController');

router.get('/test', function(req, res) {
  res.render('index');
});

router.get('/apis', function(req, res) {
  res.render('apis');
});

router.post('/signup', sysController.signup);
router.post('/signin', sysController.signin);

router.post('/refreshtoken', sysController.refreshtoken),

router.post('/signout', sysController.signout);
router.get('/user', sysController.userinfo);
router.post('/user', sysController.update);

router.post('/reset_password', sysController.reset_password);
router.get('/reset_password/:token', sysController.get_reset_password);
router.post('/reset_password/:token', sysController.post_reset_password);

module.exports = router;
