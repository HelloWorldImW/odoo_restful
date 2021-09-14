"""Common methods"""
import ast
import json
import types
import datetime
import base64

import werkzeug.wrappers


def valid_response(data, status=200, acl={}):
    """Valid Response
    This will be return when the http request was successfully processed."""
    if type(data) == list:
        for data_map in data:
            for (key,value) in data_map.items():
                value_type = type(value)
                if value_type == bytes:
                    data_map[key] = str(value, 'utf-8')
                elif value_type == datetime.datetime:
                    data_map[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                elif value_type == datetime.date:
                    data_map[key] = value.strftime("%Y-%m-%d")

    if type(data) == map:
        for (key,value) in data.items():
            value_type = type(value)
            if value_type == bytes:
                data[key] = str(value, 'utf-8')
            elif value_type == datetime.datetime:
                data[key] = value.strftime("%Y-%m-%d %H:%M:%S")
            elif value_type == datetime.date:
                data_map[key] = value.strftime("%Y-%m-%d")
            
    data = {"count": len(data), "data": data, "acl": acl}
    response = werkzeug.wrappers.Response(
        status=status,
        content_type="application/json; charset=utf-8",
        response=json.dumps(data),
    )
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    response.headers['Access-Control-Max-Age'] = 1000
    response.headers['Access-Control-Allow-Headers'] = 'origin, x-csrftoken, content-type, accept, access_token'
    return response


def invalid_response(typ, message=None, status=400):
    """Invalid Response
    This will be the return value whenever the server runs into an error
    either from the client or the server."""
    response = werkzeug.wrappers.Response(
        status=status,
        content_type="application/json; charset=utf-8",
        response=json.dumps(
            {
                "type": typ,
                "message": str(message)
                if message
                else "wrong arguments (missing validation)",
            }
        ),
    )
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    response.headers['Access-Control-Max-Age'] = 1000
    response.headers['Access-Control-Allow-Headers'] = 'origin, x-csrftoken, content-type, accept, access_token'
    return response


def extract_arguments(payload, offset=0, limit=0, order=None):
    """."""
    fields, domain = [], []
    if payload.get("domain"):
        domain += ast.literal_eval(payload.get("domain"))
    if payload.get("fields"):
        fields += ast.literal_eval(payload.get("fields"))
    if payload.get("offset"):
        offset = int(payload["offset"])
    if payload.get("limit"):
        limit = int(payload["limit"])
    if payload.get("order"):
        order = payload.get("order")
    return [domain, fields, offset, limit, order]


def extract_many2many_field(payload):
    if payload.get('many2many'):
        m2ms = payload.get('many2many')
        for many2many in ast.literal_eval(m2ms):
            valueItem = []
            (key, value), = many2many.items()
            valueItem += ast.literal_eval(value)
            payload[key] = valueItem
        payload.pop('many2many')
    if payload.get('order_line'):
        order_line_str = payload.get('order_line')
        order_line = json.loads(order_line_str)
        payload['order_line'] = order_line
    if payload.get('partner_id') and type(payload.get('partner_id')) == str:
        payload['partner_id'] = int(payload['partner_id'])
    if payload.get('partner_invoice_id') and type(payload.get('partner_invoice_id')) == str:
        payload['partner_invoice_id'] = int(payload['partner_invoice_id'])
    if payload.get('partner_shipping_id') and type(payload.get('partner_shipping_id')) == str:
        payload['partner_shipping_id'] = int(payload['partner_shipping_id'])
    return payload
