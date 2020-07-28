var express = require('express');
var passport = require('passport');
var router = express.Router();

router.get('/login',
  function  (req, res, next) {
    passport.authenticate('azuread-openidconnect',
      {
        response: res,
        prompt: 'login',
        failureRedirect: '/',
        failureFlash: true,
        successRedirect: '/'
      }
    )(req,res,next);
  }
);

router.post('/callback',
  function(req, res, next) {
    passport.authenticate('azuread-openidconnect',
      {
        response: res,
        failureRedirect: '/',
        failureFlash: true,
        successRedirect: '/auth/authenticated'
      }
    )(req,res,next);
  }
);

router.get('/authenticated',
  function(req, res, next) {
    if (req.user) {
      res.send({ authenticated: true });
    }
    res.send({ authenticated: false });
  }
);

router.get('/logout',
  function(req, res) {
    req.session.destroy(function(err) {
      req.logout();
      res.redirect('/');
    });
  }
);

module.exports = router;
