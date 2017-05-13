var express = require('express');
var router = express.Router();

var multer = require('multer');
var multerReceiverImage = multer({
  limits: {
    // 50 * 1024 * 1024
    fileSize: 52428800
  },
  fileFilter: function(req, file, cb) {
    // console.log('Upload Image : ', file);
    if (file.mimetype != "image/jpeg") {
      cb(new Error('Please upload an Image in .jpg format.'));
    } else {
      cb(null, true);
    }
  }
});

var multerReceiverVideo = multer({
  limits: {
    // 50 * 1024 * 1024
    fileSize: 52428800
  },
  fileFilter: function(req, file, cb) {
    // console.log('Upload Audio : ', file);
    if (file.mimetype != "video/mp4") {
      cb(new Error('Please upload an Video File in .mp4 format.'));
    } else {
      cb(null, true);
    }
  }
});


// Project
router.get('/test', function(req, res, next) {
  res.render('index', {title: 'Test'})
});

// router.get('/projects', Thing.getAll);
// router.get('/project/:project_id', Thing.getById);
// router.post('/project/thing/', Thing.create);
// router.put('/project/:project_id', Thing.update);
// router.delete('/project/:project_id', Thing.delete);

module.exports = router;
