#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Jakob Meng, <jakobmeng@web.de>
# Copyright (c) 2023 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

class StateMachine:

    @staticmethod
    def default_crud_functions(connection, service_name, type_name):
        session = getattr(connection, service_name)

        create_function = getattr(session, 'create_{0}'.format(type_name))
        delete_function = getattr(session, 'delete_{0}'.format(type_name))
        find_function = getattr(session, 'find_{0}'.format(type_name))
        get_function = getattr(session, 'get_{0}'.format(type_name))
        list_function = getattr(session, '{0}s'.format(type_name))
        update_function = getattr(session, 'update_{0}'.format(type_name))

        return dict(
            create=create_function,
            delete=delete_function,
            find=find_function,
            get=get_function,
            list=list_function,
            update=update_function,
        )

    def __init__(self,
                 connection,
                 sdk,
                 type_name,
                 service_name,
                 crud_functions=None,
                 **kwargs):
        for k in ['connection', 'sdk', 'service_name', 'type_name']:
            setattr(self, k, locals()[k])

        self.session = getattr(connection, service_name)

        if not crud_functions:
            crud_functions = StateMachine.default_crud_functions(
                connection, service_name, type_name)

        for k in ['create', 'delete', 'find', 'get', 'list', 'update']:
            setattr(self, '{0}_function'.format(k), crud_functions[k])

        # kwargs is for passing arguments to subclasses
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __call__(self, attributes, check_mode, state, timeout, wait,
                 updateable_attributes, non_updateable_attributes, **kwargs):
        # kwargs is for passing arguments to subclasses

        resource = self._find(attributes, **kwargs)

        if check_mode:
            return self._simulate(state, resource, attributes, timeout, wait,
                                  updateable_attributes,
                                  non_updateable_attributes, **kwargs)

        if state == 'present' and not resource:
            # Create resource
            resource = self._create(attributes, timeout, wait, **kwargs)
            return resource, True

        elif state == 'present' and resource:
            # Update resource
            update = self._build_update(resource, attributes,
                                        updateable_attributes,
                                        non_updateable_attributes, **kwargs)
            if update:
                resource = self._update(resource, timeout, update, wait,
                                        **kwargs)

            return resource, bool(update)

        elif state == 'absent' and resource:
            # Delete resource
            self._delete(resource, attributes, timeout, wait, **kwargs)
            return None, True

        elif state == 'absent' and not resource:
            # Do nothing
            return None, False

    def _build_update(self, resource, attributes, updateable_attributes,
                      non_updateable_attributes, **kwargs):
        update = {}

        # Fetch details to populate all resource attributes
        resource = self.get_function(resource['id'])

        comparison_attributes = (
            set(updateable_attributes
                if updateable_attributes is not None
                else attributes.keys())
            - set(non_updateable_attributes
                  if non_updateable_attributes is not None
                  else []))

        resource_attributes = dict(
            (k, attributes[k])
            for k in comparison_attributes
            if not self._is_equal(attributes[k], resource[k]))

        if resource_attributes:
            update['resource_attributes'] = resource_attributes

        return update

    def _create(self, attributes, timeout, wait, **kwargs):
        resource = self.create_function(**attributes)

        if wait:
            resource = self.sdk.resource.wait_for_status(self.session,
                                                         resource,
                                                         status='active',
                                                         failures=['error'],
                                                         wait=timeout,
                                                         attribute='status')

        return resource

    def _delete(self, resource, attributes, timeout, wait, **kwargs):
        self.delete_function(resource['id'])

        if wait:
            for count in self.sdk.utils.iterate_timeout(
                timeout=timeout,
                message="Timeout waiting for resource to be absent"
            ):
                if self._find(attributes) is None:
                    break

    def _freeze(self, o):
        if isinstance(o, dict):
            return frozenset((k, self._freeze(v)) for k, v in o.items())

        if isinstance(o, list):
            return tuple(self._freeze(v) for v in o)

        return o

    def _is_equal(self, a, b):
        if any([a is None and b is not None,
                a is not None and b is None]):
            return False

        if a is None and b is None:
            return True

        if isinstance(a, list) and isinstance(b, list):
            return self._freeze(a) == self._freeze(b)

        if isinstance(a, dict) and isinstance(b, dict):
            if set(a.keys()) != set(b.keys()):
                return False
            return self._freeze(a) == self._freeze(b)

        # else
        return a == b

    def _find(self, attributes, **kwargs):
        # use find_* functions for id instead of get_* functions because
        # get_* functions raise exceptions when resources cannot be found
        for k in ['id', 'name']:
            if k in attributes:
                return self.find_function(attributes[k])

        matches = list(self._find_matches(attributes, **kwargs))
        if len(matches) > 1:
            self.fail_json(msg='Found more than a single resource'
                               ' which matches the given attributes.')
        elif len(matches) == 1:
            return matches[0]
        else:  # len(matches) == 0
            return None

    def _find_matches(self, attributes, **kwargs):
        return self.list_function(**attributes)

    def _update(self, resource, timeout, update, wait, **kwargs):
        resource_attributes = update.get('resource_attributes')
        if resource_attributes:
            resource = self.update_function(resource['id'],
                                            **resource_attributes)

        if wait:
            resource = self.sdk.resource.wait_for_status(self.session,
                                                         resource,
                                                         status='active',
                                                         failures=['error'],
                                                         wait=timeout,
                                                         attribute='status')

        return resource

    def _simulate(self, state, resource, attributes, timeout, wait,
                  updateable_attributes,
                  non_updateable_attributes, **kwargs):
        if state == 'present' and not resource:
            resource = self._simulate_create(attributes, timeout, wait,
                                             **kwargs)
            return resource, True
        elif state == 'present' and resource:
            update = self._build_update(resource, attributes,
                                        updateable_attributes,
                                        non_updateable_attributes,
                                        **kwargs)
            if update:
                resource = self._simulate_update(resource, timeout, update,
                                                 wait, **kwargs)

            return resource, bool(update)
        elif state == 'absent' and resource:
            return None, True
        else:
            # state == 'absent' and not resource:
            return None, False

    def _simulate_create(self, attributes, timeout, wait, **kwargs):
        class Resource(dict):
            def to_dict(self, *args, **kwargs):
                return self

        return Resource(attributes)

    def _simulate_update(self, resource, timeout, update, wait, **kwargs):
        resource_attributes = update.get('resource_attributes')
        if resource_attributes:
            for k, v in resource_attributes.items():
                resource[k] = v

        return resource
