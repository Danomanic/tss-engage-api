const express = require('express');
const passport = require('passport');
const router = express.Router();
require('dotenv').config();


router.post('/login',
  function  (req, res, next) {
    passport.authenticate('azuread-openidconnect',
      {
        response: res,
        failureRedirect: process.env.FRONTEND_LOGIN_FAILURE,
        failureFlash: true,
        successRedirect: `${process.env.FRONTEND_LOGIN_FAILURE}&token=${req.body.id_token}`,
      }
    )(req,res,next);
  }
);

router.post('/callback',
  function(req, res, next) {
    passport.authenticate('azuread-openidconnect',
      {
        response: res,
        failureRedirect: process.env.FRONTEND_LOGIN_FAILURE,
        failureFlash: true,
        successRedirect: `${process.env.FRONTEND_LOGIN_FAILURE}&token=${req.body.id_token}`,
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
