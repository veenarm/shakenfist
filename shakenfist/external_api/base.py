import copy
import flask
import flask_restful
from flask_jwt_extended.exceptions import (
    JWTDecodeError, NoAuthorizationError, InvalidHeaderError, WrongTokenError,
    RevokedTokenError, FreshTokenRequired, CSRFError
)
from flask_jwt_extended import get_jwt_identity
import json
from jwt.exceptions import DecodeError, PyJWTError
import re
import requests
import sys
import traceback

from shakenfist.baseobject import DatabaseBackedObject as dbo
from shakenfist.config import config
from shakenfist.daemons import daemon
from shakenfist.instance import Instance
from shakenfist import logutil
from shakenfist.net import Network
from shakenfist import util

LOG, HANDLER = logutil.setup(__name__)
daemon.set_log_level(LOG, 'api')


TESTING = False


def error(status_code, message, suppress_traceback=False):
    global TESTING

    body = {
        'error': message,
        'status': status_code
    }

    _, _, tb = sys.exc_info()
    formatted_trace = traceback.format_exc()

    if TESTING or config.get('INCLUDE_TRACEBACKS'):
        if tb:
            body['traceback'] = formatted_trace

    resp = flask.Response(json.dumps(body),
                          mimetype='application/json')
    resp.status_code = status_code

    if not suppress_traceback:
        LOG.info('Returning API error: %d, %s\n    %s'
                 % (status_code, message,
                    '\n    '.join(formatted_trace.split('\n'))))
    else:
        LOG.info('Returning API error: %d, %s (traceback suppressed by caller)'
                 % (status_code, message))

    return resp


def caller_is_admin(func):
    # Ensure only users in the 'system' namespace can call this method
    def wrapper(*args, **kwargs):
        if get_jwt_identity() != 'system':
            return error(401, 'unauthorized')

        return func(*args, **kwargs)
    return wrapper


def arg_is_instance_uuid(func):
    # Method uses the instance from the db
    def wrapper(*args, **kwargs):
        if 'instance_uuid' in kwargs:
            kwargs['instance_from_db'] = Instance.from_db(
                kwargs['instance_uuid'])
        if not kwargs.get('instance_from_db'):
            LOG.with_instance(kwargs['instance_uuid']).info(
                'Instance not found, genuinely missing')
            return error(404, 'instance not found')

        return func(*args, **kwargs)
    return wrapper


def redirect_instance_request(func):
    # Redirect method to the hypervisor hosting the instance
    def wrapper(*args, **kwargs):
        i = kwargs.get('instance_from_db')
        if not i:
            return

        placement = i.placement
        if not placement:
            return
        if not placement.get('node'):
            return

        if placement.get('node') != config.NODE_NAME:
            url = 'http://%s:%d%s' % (placement['node'], config.get('API_PORT'),
                                      flask.request.environ['PATH_INFO'])
            api_token = util.get_api_token(
                'http://%s:%d' % (placement['node'], config.get('API_PORT')),
                namespace=get_jwt_identity())
            r = requests.request(
                flask.request.environ['REQUEST_METHOD'], url,
                data=json.dumps(flask_get_post_body()),
                headers={'Authorization': api_token,
                         'User-Agent': util.get_user_agent()})

            LOG.info('Proxied %s %s returns: %d, %s' % (
                     flask.request.environ['REQUEST_METHOD'], url,
                     r.status_code, r.text))
            resp = flask.Response(r.text,
                                  mimetype='application/json')
            resp.status_code = r.status_code
            return resp

        return func(*args, **kwargs)
    return wrapper


def requires_instance_ownership(func):
    # Requires that @arg_is_instance_uuid has already run
    def wrapper(*args, **kwargs):
        if not kwargs.get('instance_from_db'):
            LOG.with_field('instance', kwargs['instance_uuid']).info(
                'Instance not found, kwarg missing')
            return error(404, 'instance not found')

        i = kwargs['instance_from_db']
        if get_jwt_identity() not in [i.namespace, 'system']:
            LOG.with_instance(i).info(
                'Instance not found, ownership test in decorator')
            return error(404, 'instance not found')

        return func(*args, **kwargs)
    return wrapper


def requires_instance_active(func):
    # Requires that @arg_is_instance_uuid has already run
    def wrapper(*args, **kwargs):
        if not kwargs.get('instance_from_db'):
            LOG.with_field('instance', kwargs['instance_uuid']).info(
                'Instance not found, kwarg missing')
            return error(404, 'instance not found')

        i = kwargs['instance_from_db']
        if i.state.value != Instance.STATE_CREATED:
            LOG.with_instance(i).info(
                'Instance not ready (%s)' % i.state.value)
            return error(406, 'instance %s is not ready (%s)' % (i.uuid, i.state.value))

        return func(*args, **kwargs)
    return wrapper


def arg_is_network_uuid(func):
    # Method uses the network from the db
    def wrapper(*args, **kwargs):
        if 'network_uuid' in kwargs:
            kwargs['network_from_db'] = Network.from_db(
                kwargs['network_uuid'])
        if not kwargs.get('network_from_db'):
            LOG.with_field('network', kwargs['network_uuid']).info(
                'Network not found, missing or deleted')
            return error(404, 'network not found')

        return func(*args, **kwargs)
    return wrapper


def redirect_to_network_node(func):
    # Redirect method to the network node
    def wrapper(*args, **kwargs):
        if not util.is_network_node():
            admin_token = util.get_api_token(
                'http://%s:%d' % (config.NETWORK_NODE_IP,
                                  config.get('API_PORT')),
                namespace='system')
            r = requests.request(
                flask.request.environ['REQUEST_METHOD'],
                'http://%s:%d%s'
                % (config.NETWORK_NODE_IP,
                   config.get('API_PORT'),
                   flask.request.environ['PATH_INFO']),
                data=flask.request.data,
                headers={'Authorization': admin_token,
                         'User-Agent': util.get_user_agent()})

            LOG.info('Returning proxied request: %d, %s'
                     % (r.status_code, r.text))
            resp = flask.Response(r.text,
                                  mimetype='application/json')
            resp.status_code = r.status_code
            return resp

        return func(*args, **kwargs)
    return wrapper


def requires_network_ownership(func):
    # Requires that @arg_is_network_uuid has already run
    def wrapper(*args, **kwargs):
        log = LOG.with_field('network', kwargs['network_uuid'])

        if not kwargs.get('network_from_db'):
            log.info('Network not found, kwarg missing')
            return error(404, 'network not found')

        if get_jwt_identity() not in [kwargs['network_from_db'].namespace, 'system']:
            log.info('Network not found, ownership test in decorator')
            return error(404, 'network not found')

        return func(*args, **kwargs)
    return wrapper


def requires_network_active(func):
    # Requires that @arg_is_network_uuid has already run
    def wrapper(*args, **kwargs):
        log = LOG.with_field('network', kwargs['network_uuid'])

        if not kwargs.get('network_from_db'):
            log.info('Network not found, kwarg missing')
            return error(404, 'network not found')

        state = kwargs['network_from_db'].state
        if state.value != dbo.STATE_CREATED:
            log.info('Network not ready (%s)' % state.value)
            return error(406,
                         'network %s is not ready (%s)'
                         % (kwargs['network_from_db'].uuid, state.value))

        return func(*args, **kwargs)
    return wrapper


def flask_get_post_body():
    j = {}
    try:
        j = flask.request.get_json(force=True)
    except Exception:
        if flask.request.data:
            try:
                j = json.loads(flask.request.data)
            except Exception:
                pass
    return j


def generic_wrapper(func):
    def wrapper(*args, **kwargs):
        try:
            j = flask_get_post_body()

            if j:
                for key in j:
                    if key == 'uuid':
                        destkey = 'passed_uuid'
                    else:
                        destkey = key
                    kwargs[destkey] = j[key]

            formatted_headers = []
            for header in flask.request.headers:
                formatted_headers.append(str(header))

            # Ensure key does not appear in logs
            kwargs_log = copy.copy(kwargs)
            if 'key' in kwargs_log:
                kwargs_log['key'] = '*****'

            msg = 'API request: %s %s' % (
                flask.request.method, flask.request.url)
            msg += '\n    Args: %s\n    KWargs: %s' % (args, kwargs_log)

            if re.match(r'http(|s)://0.0.0.0:\d+/$', flask.request.url):
                LOG.debug(msg)
            else:
                LOG.info(msg)

            return func(*args, **kwargs)

        except TypeError as e:
            return error(400, str(e), suppress_traceback=True)

        except DecodeError:
            # Send a more informative message than 'Not enough segments'
            return error(401, 'invalid JWT in Authorization header',
                         suppress_traceback=True)

        except (JWTDecodeError,
                NoAuthorizationError,
                InvalidHeaderError,
                WrongTokenError,
                RevokedTokenError,
                FreshTokenRequired,
                CSRFError,
                PyJWTError,
                ) as e:
            return error(401, str(e), suppress_traceback=True)

        except Exception as e:
            LOG.exception('Server error')
            return error(500, 'server error: %s' % repr(e),
                         suppress_traceback=True)

    return wrapper


class Resource(flask_restful.Resource):
    method_decorators = [generic_wrapper]