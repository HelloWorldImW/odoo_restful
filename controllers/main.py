"""Part of odoo. See LICENSE file for full copyright and licensing details."""
import base64
import functools
import json
import logging
import os

import werkzeug

import odoo
from odoo import http
from odoo.http import request
from ..common import (
    extract_arguments,
    invalid_response,
    valid_response, extract_many2many_field,
)

_logger = logging.getLogger(__name__)


def validate_token(func):
    """."""

    @functools.wraps(func)
    def wrap(self, *args, **kwargs):
        """."""
        access_token = request.httprequest.headers.get("access_token") or kwargs.get(
            'access_token') or request.httprequest.headers.get("accept")
        if not access_token:
            return invalid_response(
                "access_token_not_found", "missing access token in request header", 401
            )

        access_token_data = (
            request.env["api.access_token"]
                .sudo()
                .search([("token", "=", access_token)], order="id DESC", limit=1)
        )
        if (
            access_token_data.find_one_or_create_token(
                user_id=access_token_data.user_id.id
            )
            != access_token
        ):
            return invalid_response(
                "access_token", "token seems to have expired or invalid", 401
            )

        request.session.uid = access_token_data.user_id.id
        request.uid = access_token_data.user_id.id
        return func(self, *args, **kwargs)

    return wrap


def binary_content(xmlid=None, model='ir.attachment', id=None, field='datas', unique=False, filename=None,
                   filename_field='datas_fname', download=False, mimetype=None,
                   default_mimetype='application/octet-stream', env=None):
    return request.registry['ir.http'].binary_content(
        xmlid=xmlid, model=model, id=id, field=field, unique=unique, filename=filename, filename_field=filename_field,
        download=download, mimetype=mimetype, default_mimetype=default_mimetype, env=env)


_routes = ["/api/<model>", "/api/<model>/<id>"]


class APIController(http.Controller):
    """."""

    def __init__(self):
        self._model = "ir.model"

    @validate_token
    @http.route('/api/rights/<model>', type="http", auth="none", methods=["GET"], csrf=False, cors="*")
    def get_rights(self, model=None, **payload):

        Comodel = request.env[model]
        acl = {
            'can_create': 'true' if Comodel.check_access_rights('create', raise_exception=False) else 'false',
            'can_write': 'true' if Comodel.check_access_rights('write', raise_exception=False) else 'false',
            'is_erp_manager': 'true' if request.env.user.has_group('base.group_erp_manager') else 'false'
        }
        
        return valid_response(data={}, acl=acl)

    @validate_token
    @http.route("/api/user/<model>", type="http", auth="none", methods=["GET"], csrf=False, cors="*")
    def get_byuser(self, model=None, **payload):
        ioc_name = model
        model = request.env[self._model].sudo().search([("model", "=", model)], limit=1)
        if model:
            Comodel = request.env[ioc_name]
            acl = {
                'can_create': 'true' if Comodel.check_access_rights('create', raise_exception=False) else 'false',
                'can_write': 'true' if Comodel.check_access_rights('write', raise_exception=False) else 'false'
            }
            domain, fields, offset, limit, order = extract_arguments(payload)
            try:
                data = request.env[model.model].search_read(
                    domain=domain, fields=fields, offset=offset,
                    limit=limit, order=order,
                )
                return valid_response(data=data, acl=acl)
            except Exception as e:
                return invalid_response("Exception", e)
        return invalid_response(
            "invalid object model",
            "The model %s is not available in the registry." % ioc_name,
        )

    @validate_token
    @http.route(_routes, type="http", auth="none", methods=["GET"], csrf=False, cors="*")
    def get(self, model=None, id=None, **payload):
        ioc_name = model
        model = request.env[self._model].sudo().search([("model", "=", model)], limit=1)
        if model:
            Comodel = request.env[ioc_name]
            acl = {
                'can_create': 'true' if Comodel.check_access_rights('create', raise_exception=False) else 'false',
                'can_write': 'true' if Comodel.check_access_rights('write', raise_exception=False) else 'false'
            }
            domain, fields, offset, limit, order = extract_arguments(payload)
            try:
                if id:
                    domain.append(('id', '=', id))

                data = request.env[model.model].sudo().search_read(
                    domain=domain, fields=fields, offset=offset,
                    limit=limit, order=order,
                )
                return valid_response(data=data, acl=acl)
            except Exception as e:
                return invalid_response("Exception", e)
        return invalid_response(
            "invalid object model",
            "The model %s is not available in the registry." % ioc_name,
        )

    @validate_token
    @http.route('/api/<model>', type="http", auth="none", methods=["POST"], csrf=False, cors="*")
    def create(self, model=None, id=None, **payload):
        """Create a new record.
        Basic sage:
        import requests

        headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'charset': 'utf-8',
            'access-token': 'access_token'
        }
        data = {
            'name': 'Babatope Ajepe',
            'country_id': 105,
            'child_ids': [
                {
                    'name': 'Contact',
                    'type': 'contact'
                },
                {
                    'name': 'Invoice',
                   'type': 'invoice'
                }
            ],
            'category_id': [{'id': 9}, {'id': 10}]
        }
        req = requests.post('%s/api/res.partner/' %
                            base_url, headers=headers, data=data)

        """
        ioc_name = model
        model = request.env[self._model].sudo().search([("model", "=", model)], limit=1)
        if model:
            payload = extract_many2many_field(payload)
            try:
                resource = request.env[model.model].with_context({"from_mobile": True}).create(payload)
            except Exception as e:
                return invalid_response("params", e)
            return valid_response({'id': resource.id})
        return invalid_response(
            "invalid object model",
            "The model %s is not available in the registry." % ioc_name,
        )

    @validate_token
    @http.route("/api/<model>/<id>", type="http", auth="none", methods=["POST"], csrf=False, cors='*')
    def write(self, model=None, id=None, **payload):
        try:
            _id = int(id)
        except Exception as e:
            return invalid_response(
                "invalid object id", "invalid literal %s for id with base " % id
            )
        _model = (
            request.env[self._model].sudo().search([("model", "=", model)], limit=1)
        )
        if not _model:
            return invalid_response(
                "invalid object model",
                "The model %s is not available in the registry." % model,
                404,
            )

        payload = extract_many2many_field(payload)
        try:
            request.env[_model.model].sudo().browse(_id).write(payload)
        except Exception as e:
            _logger.error(e)
            return invalid_response("exception", e)
        else:
            return valid_response(
                {'code': '0',
                 'data': "update %s record with id %s successfully!" % (_model.model, _id)}
            )

    @validate_token
    @http.route(_routes, type="http", auth="none", methods=["DELETE"], csrf=False, cors='*')
    def delete(self, model=None, id=None, **payload):
        """."""
        try:
            _id = int(id)
        except Exception as e:
            return invalid_response(
                "invalid object id", "invalid literal %s for id with base " % id
            )
        try:
            record = request.env[model].sudo().search([("id", "=", _id)])
            if record:
                record.unlink()
            else:
                return invalid_response(
                    "missing_record",
                    "record object with id %s could not be found" % _id,
                    404,
                )
        except Exception as e:
            return invalid_response("exception", e.name, 503)
        else:
            return valid_response("record %s has been successfully deleted" % record.id)

    @validate_token
    @http.route(_routes, type="http", auth="none", methods=["PATCH"], csrf=False, cors='*')
    def patch(self, model=None, id=None, action=None, **payload):
        """."""
        try:
            _id = int(id)
        except Exception as e:
            return invalid_response(
                "invalid object id", "invalid literal %s for id with base " % id
            )
        try:
            record = request.env[model].sudo().search([("id", "=", _id)])
            _callable = action in [
                method for method in dir(record) if callable(getattr(record, method))
            ]
            if record and _callable:
                # action is a dynamic variable.
                getattr(record, action)()
            else:
                return invalid_response(
                    "missing_record",
                    "record object with id %s could not be found or %s object has no method %s"
                    % (_id, model, action),
                    404,
                )
        except Exception as e:
            return invalid_response("exception", e, 503)
        else:
            return valid_response("record %s has been successfully patched" % record.id)

    @validate_token
    @http.route("/api/<model>/<id>/<action>", type="http", auth="none", methods=["POST"], csrf=False, cors='*')
    def action(self, model=None, id=None, action=None, **payload):
        """."""
        try:
            _id = int(id)
        except Exception as e:
            return invalid_response(
                "invalid object id", "invalid literal %s for id with base " % id
            )
        try:
            record = request.env[model].search([("id", "=", _id)])
            _callable = action in [
                method for method in dir(record) if callable(getattr(record, method))
            ]
            if record and _callable:
                # action is a dynamic variable.
                getattr(record, action)()
            else:
                return invalid_response(
                    "missing_record",
                    "record object with id %s could not be found or %s object has no method %s"
                    % (_id, model, action),
                    404,
                )
        except Exception as e:
            return invalid_response("exception", e, 503)
        else:
            return valid_response("record %s has been successfully patched" % record.id)

    @validate_token
    @http.route('/detail/<model>/<id>', type="http", auth="none", methods=["GET"], csrf=False, cors="*")
    def get_detail(self, model, id, **payload):
        ioc_name = model
        model = request.env[self._model].sudo().search([("model", "=", model)], limit=1)
        if model:
            domain, fields, offset, limit, order = extract_arguments(payload)
            try:
                model_env = request.env[model.model]
                record = model_env.sudo().browse(int(id))
                result = {}
                if not record:
                    return result

                items = model_env._fields.items()
                for item in items:
                    name = item[0]
                    no_get_list = ['groups_id', 'message_follower_ids', 'message_ids', 'log_ids', 'token_ids']
                    if item[1].type == 'one2many' or item[1].type == 'many2many':
                        if name in no_get_list:
                            continue
                        models = getattr(record, name)
                        if hasattr(record, name):
                            result[name] = models.mapped('display_name')
                            continue
                    elif item[1].type == 'many2one':
                        m = getattr(record, name)
                        if m and hasattr(m, 'name'):
                            result[name] = m.name
                        else:
                            result[name] = ''
                        continue
                    elif item[1].type == 'selection':
                        m = getattr(record, name)
                        dic = dict(model_env.fields_get(allfields=[name])[name]['selection'])
                        if dic.get(m):
                            result[name] = dic.get(m)
                        continue
                    if hasattr(record, name):
                        result[name] = record[name]
                return valid_response(result)
            except Exception as e:
                return invalid_response("Exception", e)
        return invalid_response(
            "invalid object model",
            "The model %s is not available in the registry." % ioc_name,
        )

    @http.route('/api/<model>/create_user', type="http", auth="none", methods=["POST"], csrf=False, cors="*")
    def createUser(self, model=None, id=None, **payload):
        ioc_name = model
        model = request.env[self._model].sudo().search([("model", "=", model)], limit=1)
        if model:
            try:
                resource = request.env[model.model].sudo().create(payload)
            except Exception as e:
                return invalid_response("params", e)
            return valid_response({'id': resource.id, 'partner_id': resource.partner_id.id})
        return invalid_response(
            "invalid object model",
            "The model %s is not available in the registry." % ioc_name,
        )

    @http.route('/write/res.partner/<id>', type="http", auth="none", methods=["POST"], csrf=False, cors="*")
    def writePartner(self, id=None, **payload):
        _model = 'res.partner'
        try:
            _id = int(id)
        except Exception as e:
            return invalid_response(
                "invalid object id", "invalid literal %s for id with base " % id
            )
        try:
            request.env[_model].sudo().browse(_id).write(payload)
        except Exception as e:
            return invalid_response("exception", e.name)
        else:
            return json.dumps(
                {'code': '0',
                 'data': "update %s record with id %s successfully!" % (_model, _id)}
            )

    @validate_token
    @http.route(['/myweb/image',
                 '/myweb/image/<int:id>',
                 '/myweb/image/<int:id>/<string:filename>',
                 '/myweb/image/<int:id>/<int:width>x<int:height>',
                 '/myweb/image/<int:id>/<int:width>x<int:height>/<string:filename>'
                 ], type="http", auth="none", methods=["GET"], csrf=False, cors="*")
    def content_image(self, xmlid=None, model='ir.attachment', id=None, field='datas',
                      filename_field='datas_fname', unique=None, filename=None, mimetype=None,
                      download=None, width=0, height=0, crop=False, related_id=None, access_mode=None,
                      access_token=None, avoid_if_small=False, upper_limit=False, signature=False, **kw):
        status, headers, content = binary_content(
            xmlid=xmlid, model=model, id=id, field=field, unique=unique, filename=filename,
            filename_field=filename_field, download=download, mimetype=mimetype,
            default_mimetype='image/png',
            env=request.env)
        if status == 304:
            return werkzeug.wrappers.Response(status=304, headers=headers)
        elif status == 301:
            return werkzeug.utils.redirect(content, code=301)
        elif status != 200 and download:
            return request.not_found()

        if headers and dict(headers).get('Content-Type', '') == 'image/svg+xml':  # we shan't resize svg images
            height = 0
            width = 0
        else:
            height = int(height or 0)
            width = int(width or 0)

        if not content:
            content = base64.b64encode(self.placeholder(image='placeholder.png'))
            headers = self.force_contenttype(headers, contenttype='image/png')
            if not (width or height):
                suffix = field.split('_')[-1]
                if suffix in ('small', 'medium', 'big'):
                    content = getattr(odoo.tools, 'image_resize_image_%s' % suffix)(content)

        elif (width or height):
            if not upper_limit:
                # resize maximum 500*500
                if width > 500:
                    width = 500
                if height > 500:
                    height = 500
            content = odoo.tools.image_resize_image(base64_source=content, size=(width or None, height or None),
                                                    encoding='base64',
                                                    avoid_if_small=avoid_if_small)

        image_base64 = base64.b64decode(content)
        headers.append(('Content-Length', len(image_base64)))
        response = request.make_response(image_base64, headers)
        response.status_code = status
        return response

    @validate_token
    @http.route(['/myweb/content',
                 '/myweb/content/<string:xmlid>',
                 '/myweb/content/<string:xmlid>/<string:filename>',
                 '/myweb/content/<int:id>',
                 '/myweb/content/<int:id>/<string:filename>',
                 '/myweb/content/<int:id>-<string:unique>',
                 '/myweb/content/<int:id>-<string:unique>/<string:filename>',
                 '/myweb/content/<string:model>/<int:id>/<string:field>',
                 '/myweb/content/<string:model>/<int:id>/<string:field>/<string:filename>'], type='http', auth="public")
    def content_common(self, xmlid=None, model='ir.attachment', id=None, field='datas', filename=None,
                       filename_field='datas_fname', unique=None, mimetype=None, download=None, data=None, token=None,
                       **kw):
        status, headers, content = binary_content(xmlid=xmlid, model=model, id=id, field=field, unique=unique,
                                                  filename=filename, filename_field=filename_field, download=download,
                                                  mimetype=mimetype)
        if status == 304:
            response = werkzeug.wrappers.Response(status=status, headers=headers)
        elif status == 301:
            return werkzeug.utils.redirect(content, code=301)
        elif status != 200:
            response = request.not_found()
        else:
            content_base64 = base64.b64decode(content)
            headers.append(('Content-Length', len(content_base64)))
            response = request.make_response(content_base64, headers)
        if token:
            response.set_cookie('fileToken', token)
        return response

    def placeholder(self, image='placeholder.png'):
        addons_path = http.addons_manifest['web']['addons_path']
        return open(os.path.join(addons_path, 'web', 'static', 'src', 'img', image), 'rb').read()

    def force_contenttype(self, headers, contenttype='image/png'):
        dictheaders = dict(headers)
        dictheaders['Content-Type'] = contenttype
        return dictheaders.items()
