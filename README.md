### Odoo RESTful API(restful)
在odoo10的Restful模块的基础上做了odoo14的适配, 改了一些bug, 添加了微信登录
> This is an HTTP framework that only cares about generating an HTTP response for each HTTP
request. 
In other to use this module, a basic understating of Odoo RPC interface is required(though not that neccessary) especially when dealing with Many2many and One2many relationship. The implementation sits on the existing Odoo RPC features, data structures  and format when creating or delecting Odoo's records are still applicable. I will be demostrating the usage using python request library.

#### Access token request
An access token is required in other to be able to perform any operations and ths token once generated should alway be send a long side any subsequents request.
##### 微信登录:
```python
import requests, json

headers = {
    'content-type': 'application/x-www-form-urlencoded',
    'charset':'utf-8'
}

data = {
    'open_id': 'wxxxxas00111111',
    'nick_name': 'admin',
}
base_url = 'http://theninnercicle.com.ng'

req = requests.get('{}/api/wxauth/token'.format(base_url), data=data, headers=headers)

content = json.loads(req.content.decode('utf-8'))

headers['access-token'] = content.get('access_token') # add the access token to the header
print(headers)
```

##### 用户名密码登录:
```python
import requests, json

headers = {
    'content-type': 'application/x-www-form-urlencoded',
    'charset':'utf-8'
}

data = {
    'login': 'admin',
    'password': 'admin',
    'db': 'demo_db'
}
base_url = 'http://theninnercicle.com.ng'

req = requests.get('{}/api/auth/token'.format(base_url), data=data, headers=headers)

content = json.loads(req.content.decode('utf-8'))

headers['access-token'] = content.get('access_token') # add the access token to the header
print(headers)
```
### To delete acccess-token

```python
req = requests.delete('%s/api/auth/token'%base_url, data=data, headers=headers)
```
### [GET]
```python
req = requests.get('{}/api/sale.order/'.format(base_url), headers=headers,
                   data={'limit': 10, 'domain': []})
# ***Pass optional parameter like this ***
{
  'limit': 10, 'domain': "[('supplier','=',True),('parent_id','=', False)]",
  'order': 'name asc', 'offset': 10
}

print(req.content)

```
### [POST]
```python

**POST request**
```python
p = requests.post('%s/api/res.partner/'%base_url, headers=headers,
                  data=json.dumps({
    'name':'John',
    'country_id': 105,
    'child_ids': [{'name': 'Contact', 'type':'contact'},
                  {'name': 'Invoice', 'type':'invoice'}],
    'category_id': [{'id':9}, {'id': 10}]
    }
))
print(p.content)
```

**PUT Request**
```python
p = requests.put('http://theninnercicle.com.ng/api/res.partner/68', headers=headers,
                 data=json.dumps({
    'name':'John Doe',
    'country_id': 107,
    'category_id': [{'id': 10}]
    }
))
print(p.content)
```

**DELETE Request**
```python
p = requests.delete('http://theninnercicle.com.ng/api/res.partner/68', headers=headers)
print(p.content)
```
