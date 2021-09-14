# -*- coding: utf-8 -*-
# Part of odoo. See LICENSE file for full copyright and licensing details.
import json
import logging

import werkzeug.wrappers

from odoo import http
from ..common import invalid_response, valid_response
from odoo.http import request

_logger = logging.getLogger(__name__)

expires_in = "restful.access_token_expires_in"


class APIToken(http.Controller):
    """."""

    def __init__(self):

        self._token = request.env["api.access_token"]
        self._expires_in = request.env.ref(expires_in).sudo().value

    @http.route("/api/auth/token", methods=["GET"], type="http", auth="none", csrf=False, cors="*")
    def token(self, **post):
        """The token URL to be used for getting the access_token:

        Args:
            **post must contain login and password.
        Returns:

            returns https response code 404 if failed error message in the body in json format
            and status code 202 if successful with the access_token.
        Example:
           import requests

           headers = {'content-type': 'text/plain', 'charset':'utf-8'}

           data = {
               'login': 'admin',
               'password': 'admin',
               'db': 'galago.ng'
            }
           base_url = 'http://odoo.ng'
           eq = requests.post(
               '{}/api/auth/token'.format(base_url), data=data, headers=headers)
           content = json.loads(req.content.decode('utf-8'))
           headers.update(access-token=content.get('access_token'))
        """
        _token = request.env["api.access_token"]
        params = ["db", "login", "password"]
        params = {key: post.get(key) for key in params if post.get(key)}
        db, username, password = post.get("db"), post.get("login"), post.get("password")
        if not all([db, username, password]):
            # Empty 'db' or 'username' or 'password:
            return invalid_response(
                400,
                "missing error",
                "either of the following are missing [db, username,password]",
            )
        # Login in odoo database:
        try:
            request.session.authenticate(db, username, password)
        except Exception as e:
            # Invalid database:
            info = "The database name is not valid {}".format((e))
            error = "invalid_database"
            _logger.error(info)
            return invalid_response(400, error, info)

        uid = request.session.uid
        groups = ''
        # odoo login failed:
        if not uid:
            info = "authentication failed"
            error = "authentication failed"
            _logger.error(info)
            return invalid_response(401, error, info)
        else:
            _groups = request.env['res.users'].browse(uid).groups_id.mapped('display_name')
            groups = ','.join(_groups)

        partner_id = request.env['res.users'].browse(uid).partner_id.id
        # Generate tokens
        access_token = _token.find_one_or_create_token(user_id=uid, create=True)
        # Successful response:
        return werkzeug.wrappers.Response(
            status=200,
            content_type="application/json; charset=utf-8",
            headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
            response=json.dumps(
                {
                    "uid": uid,
                    "partner_id": partner_id,
                    "user_context": request.session.get_context() if uid else {},
                    "company_id": request.env.user.company_id.id if uid else None,
                    "access_token": access_token,
                    "expires_in": self._expires_in,
                    "groups": groups
                }
            ),
        )

    
    '''
    @description: 微信登录
    @param {
        * nick_name 微信昵称
        * open_id 微信openID
        }
    @return {*}
    '''
    @http.route("/api/wxauth/token", type="http", auth="public", csrf=False)
    def wx_token(self, **post):
        _token = request.env["api.access_token"]
        params = ["open_id", "nick_name"]
        params = {key: post.get(key) for key in params if post.get(key)}
        open_id, nick_name = post.get("open_id"), post.get("nick_name")
        if not open_id:
            return invalid_response(
                400,
                "missing error",
                "either of the following are missing open_id",
            )
        _user = request.env["res.users"]
        wx_open_id = _user.search([('wechat_open_id', '=', open_id)], limit = 1).wechat_open_id
        if not wx_open_id:
            values = {
                'login': open_id,
                'name': nick_name,
                'wechat_nick_name': nick_name,
                'wechat_open_id': open_id,
                'password': open_id
            }
            try:
                _user.sudo().signup(values, False)
            except Exception as e:
                return invalid_response(
                    400,
                    "用户创建失败",
                    e.message,
                )
        uid = _user.search([('wechat_open_id', '=', open_id)], limit = 1).id
        groups = ''
        _groups = _user.browse(uid).groups_id.mapped('display_name')
        groups = ','.join(_groups)

        partner_id = _user.browse(uid).partner_id.id
        access_token = _token.find_one_or_create_token(user_id=uid, create=True)
        return werkzeug.wrappers.Response(
            status=200,
            content_type="application/json; charset=utf-8",
            headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
            response=json.dumps(
                {
                    "uid": uid,
                    "partner_id": partner_id,
                    "user_context": {},
                    "company_id": request.env.user.company_id.id if uid else None,
                    "access_token": access_token,
                    "expires_in": self._expires_in,
                    "groups": groups
                }
            ),
        )

    @http.route("/api/auth/token", methods=["DELETE"], type="http", auth="none", csrf=False)
    def delete(self, **post):
        """."""
        _token = request.env["api.access_token"]
        access_token = request.httprequest.headers.get("access_token")
        access_token = _token.search([("token", "=", access_token)])
        if not access_token:
            info = "No access token was provided in request!"
            error = "no_access_token"
            _logger.error(info)
            return invalid_response(400, error, info)
        for token in access_token:
            token.unlink()
        # Successful response:
        return valid_response(
            200, {"desc": "token successfully deleted", "delete": True}
        )
