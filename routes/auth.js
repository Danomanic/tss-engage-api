const express = require('express');
const passport = require('passport');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/user');
require('dotenv').config();


router.post('/login',
  function  (req, res, next) {
    passport.authenticate('azuread-openidconnect',
      {
        response: res,
        failureRedirect: process.env.FRONTEND_LOGIN_FAILURE,
        failureFlash: true,
        successRedirect: `${process.env.FRONTEND_LOGIN_SUCCESS}&token=${req.body.id_token}`,
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
        successRedirect: `${process.env.FRONTEND_LOGIN_SUCCESS}&token=${req.body.id_token}`,
      }
    )(req,res,next);
  }
);

router.post('/authenticated',
  async function(req, res, next) {
    var decoded = jwt.decode(req.body.token);
    const user = await User.findOne({ oid: decoded.oid });
    if (user !== null && user !== undefined) {
      res.send({ authenticated: true });
    } else {
      res.send({ authenticated: false });
    }
  }
);

router.post('/logout',
  function(req, res) {
    const decoded = jwt.decode(req.body.token);
    req.session.destroy(function(err) {
      req.logout();
      User.findOneAndDelete({ oid: decoded.oid })
      res.redirect(process.env.FRONTEND_LOGIN_SUCCESS);
    });
  }
);

module.exports = router;
