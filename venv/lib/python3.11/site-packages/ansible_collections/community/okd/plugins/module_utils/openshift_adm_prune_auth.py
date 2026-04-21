#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils._text import to_native

from ansible_collections.community.okd.plugins.module_utils.openshift_common import (
    AnsibleOpenshiftModule,
)

try:
    from kubernetes import client
    from kubernetes.dynamic.exceptions import DynamicApiError, NotFoundError
except ImportError:
    pass


class OpenShiftAdmPruneAuth(AnsibleOpenshiftModule):
    def __init__(self, **kwargs):
        super(OpenShiftAdmPruneAuth, self).__init__(**kwargs)

    def prune_resource_binding(
        self, kind, api_version, ref_kind, ref_namespace_names, propagation_policy=None
    ):
        resource = self.find_resource(kind=kind, api_version=api_version, fail=True)
        candidates = []
        for ref_namespace, ref_name in ref_namespace_names:
            try:
                result = resource.get(name=None, namespace=ref_namespace)
                result = result.to_dict()
                result = result.get("items") if "items" in result else [result]
                for obj in result:
                    namespace = obj["metadata"].get("namespace", None)
                    name = obj["metadata"].get("name")
                    if ref_kind and obj["roleRef"]["kind"] != ref_kind:
                        # skip this binding as the roleRef.kind does not match
                        continue
                    if obj["roleRef"]["name"] == ref_name:
                        # select this binding as the roleRef.name match
                        candidates.append((namespace, name))
            except NotFoundError:
                continue
            except DynamicApiError as exc:
                msg = "Failed to get {kind} resource due to: {msg}".format(
                    kind=kind, msg=exc.body
                )
                self.fail_json(msg=msg)
            except Exception as e:
                msg = "Failed to get {kind} due to: {msg}".format(
                    kind=kind, msg=to_native(e)
                )
                self.fail_json(msg=msg)

        if len(candidates) == 0 or self.check_mode:
            return [y if x is None else x + "/" + y for x, y in candidates]

        delete_options = client.V1DeleteOptions()
        if propagation_policy:
            delete_options.propagation_policy = propagation_policy

        for namespace, name in candidates:
            try:
                result = resource.delete(
                    name=name, namespace=namespace, body=delete_options
                )
            except DynamicApiError as exc:
                msg = "Failed to delete {kind} {namespace}/{name} due to: {msg}".format(
                    kind=kind, namespace=namespace, name=name, msg=exc.body
                )
                self.fail_json(msg=msg)
            except Exception as e:
                msg = "Failed to delete {kind} {namespace}/{name} due to: {msg}".format(
                    kind=kind, namespace=namespace, name=name, msg=to_native(e)
                )
                self.fail_json(msg=msg)
        return [y if x is None else x + "/" + y for x, y in candidates]

    def update_resource_binding(self, ref_kind, ref_names, namespaced=False):
        kind = "ClusterRoleBinding"
        api_version = "rbac.authorization.k8s.io/v1"
        if namespaced:
            kind = "RoleBinding"
        resource = self.find_resource(kind=kind, api_version=api_version, fail=True)
        result = resource.get(name=None, namespace=None).to_dict()
        result = result.get("items") if "items" in result else [result]

        if len(result) == 0:
            return [], False

        def _update_user_group(binding_namespace, subjects):
            users, groups = [], []
            for x in subjects:
                if x["kind"] == "User":
                    users.append(x["name"])
                elif x["kind"] == "Group":
                    groups.append(x["name"])
                elif x["kind"] == "ServiceAccount":
                    namespace = binding_namespace
                    if x.get("namespace") is not None:
                        namespace = x.get("namespace")
                    if namespace is not None:
                        users.append(
                            "system:serviceaccount:%s:%s" % (namespace, x["name"])
                        )
            return users, groups

        candidates = []
        changed = False
        for item in result:
            subjects = item.get("subjects", [])
            retainedSubjects = [
                x for x in subjects if x["kind"] == ref_kind and x["name"] in ref_names
            ]
            if len(subjects) != len(retainedSubjects):
                updated_binding = item
                updated_binding["subjects"] = retainedSubjects
                binding_namespace = item["metadata"].get("namespace", None)
                (
                    updated_binding["userNames"],
                    updated_binding["groupNames"],
                ) = _update_user_group(binding_namespace, retainedSubjects)
                candidates.append(
                    binding_namespace + "/" + item["metadata"]["name"]
                    if binding_namespace
                    else item["metadata"]["name"]
                )
                changed = True
                if not self.check_mode:
                    try:
                        resource.apply(updated_binding, namespace=binding_namespace)
                    except DynamicApiError as exc:
                        msg = "Failed to apply object due to: {0}".format(exc.body)
                        self.fail_json(msg=msg)
        return candidates, changed

    def update_security_context(self, ref_names, key):
        params = {
            "kind": "SecurityContextConstraints",
            "api_version": "security.openshift.io/v1",
        }
        sccs = self.kubernetes_facts(**params)
        if not sccs["api_found"]:
            self.fail_json(msg=sccs["msg"])
        sccs = sccs.get("resources")

        candidates = []
        changed = False
        resource = self.find_resource(
            kind="SecurityContextConstraints", api_version="security.openshift.io/v1"
        )
        for item in sccs:
            subjects = item.get(key, [])
            retainedSubjects = [x for x in subjects if x not in ref_names]
            if len(subjects) != len(retainedSubjects):
                candidates.append(item["metadata"]["name"])
                changed = True
                if not self.check_mode:
                    upd_sec_ctx = item
                    upd_sec_ctx.update({key: retainedSubjects})
                    try:
                        resource.apply(upd_sec_ctx, namespace=None)
                    except DynamicApiError as exc:
                        msg = "Failed to apply object due to: {0}".format(exc.body)
                        self.fail_json(msg=msg)
        return candidates, changed

    def auth_prune_roles(self):
        params = {
            "kind": "Role",
            "api_version": "rbac.authorization.k8s.io/v1",
            "namespace": self.params.get("namespace"),
        }
        for attr in ("name", "label_selectors"):
            if self.params.get(attr):
                params[attr] = self.params.get(attr)

        result = self.kubernetes_facts(**params)
        if not result["api_found"]:
            self.fail_json(msg=result["msg"])

        roles = result.get("resources")
        if len(roles) == 0:
            self.exit_json(
                changed=False,
                msg="No candidate rolebinding to prune from namespace %s."
                % self.params.get("namespace"),
            )

        ref_roles = [(x["metadata"]["namespace"], x["metadata"]["name"]) for x in roles]
        candidates = self.prune_resource_binding(
            kind="RoleBinding",
            api_version="rbac.authorization.k8s.io/v1",
            ref_kind="Role",
            ref_namespace_names=ref_roles,
            propagation_policy="Foreground",
        )
        if len(candidates) == 0:
            self.exit_json(changed=False, role_binding=candidates)

        self.exit_json(changed=True, role_binding=candidates)

    def auth_prune_clusterroles(self):
        params = {"kind": "ClusterRole", "api_version": "rbac.authorization.k8s.io/v1"}
        for attr in ("name", "label_selectors"):
            if self.params.get(attr):
                params[attr] = self.params.get(attr)

        result = self.kubernetes_facts(**params)
        if not result["api_found"]:
            self.fail_json(msg=result["msg"])

        clusterroles = result.get("resources")
        if len(clusterroles) == 0:
            self.exit_json(
                changed=False, msg="No clusterroles found matching input criteria."
            )

        ref_clusterroles = [(None, x["metadata"]["name"]) for x in clusterroles]

        # Prune ClusterRoleBinding
        candidates_cluster_binding = self.prune_resource_binding(
            kind="ClusterRoleBinding",
            api_version="rbac.authorization.k8s.io/v1",
            ref_kind=None,
            ref_namespace_names=ref_clusterroles,
        )

        # Prune Role Binding
        candidates_namespaced_binding = self.prune_resource_binding(
            kind="RoleBinding",
            api_version="rbac.authorization.k8s.io/v1",
            ref_kind="ClusterRole",
            ref_namespace_names=ref_clusterroles,
        )

        self.exit_json(
            changed=True,
            cluster_role_binding=candidates_cluster_binding,
            role_binding=candidates_namespaced_binding,
        )

    def list_groups(self, params=None):
        options = {"kind": "Group", "api_version": "user.openshift.io/v1"}
        if params:
            for attr in ("name", "label_selectors"):
                if params.get(attr):
                    options[attr] = params.get(attr)
        return self.kubernetes_facts(**options)

    def auth_prune_users(self):
        params = {"kind": "User", "api_version": "user.openshift.io/v1"}
        for attr in ("name", "label_selectors"):
            if self.params.get(attr):
                params[attr] = self.params.get(attr)

        users = self.kubernetes_facts(**params)
        if len(users) == 0:
            self.exit_json(
                changed=False,
                msg="No resource type 'User' found matching input criteria.",
            )

        names = [x["metadata"]["name"] for x in users]
        changed = False
        # Remove the user role binding
        rolebinding, changed_role = self.update_resource_binding(
            ref_kind="User", ref_names=names, namespaced=True
        )
        changed = changed or changed_role
        # Remove the user cluster role binding
        clusterrolesbinding, changed_cr = self.update_resource_binding(
            ref_kind="User", ref_names=names
        )
        changed = changed or changed_cr

        # Remove the user from security context constraints
        sccs, changed_sccs = self.update_security_context(names, "users")
        changed = changed or changed_sccs

        # Remove the user from groups
        groups = self.list_groups()
        deleted_groups = []
        resource = self.find_resource(kind="Group", api_version="user.openshift.io/v1")
        for grp in groups:
            subjects = grp.get("users", [])
            retainedSubjects = [x for x in subjects if x not in names]
            if len(subjects) != len(retainedSubjects):
                deleted_groups.append(grp["metadata"]["name"])
                changed = True
                if not self.check_mode:
                    upd_group = grp
                    upd_group.update({"users": retainedSubjects})
                    try:
                        resource.apply(upd_group, namespace=None)
                    except DynamicApiError as exc:
                        msg = "Failed to apply object due to: {0}".format(exc.body)
                        self.fail_json(msg=msg)

        # Remove the user's OAuthClientAuthorizations
        oauth = self.kubernetes_facts(
            kind="OAuthClientAuthorization", api_version="oauth.openshift.io/v1"
        )
        deleted_auths = []
        resource = self.find_resource(
            kind="OAuthClientAuthorization", api_version="oauth.openshift.io/v1"
        )
        for authorization in oauth:
            if authorization.get("userName", None) in names:
                auth_name = authorization["metadata"]["name"]
                deleted_auths.append(auth_name)
                changed = True
                if not self.check_mode:
                    try:
                        resource.delete(
                            name=auth_name,
                            namespace=None,
                            body=client.V1DeleteOptions(),
                        )
                    except DynamicApiError as exc:
                        msg = "Failed to delete OAuthClientAuthorization {name} due to: {msg}".format(
                            name=auth_name, msg=exc.body
                        )
                        self.fail_json(msg=msg)
                    except Exception as e:
                        msg = "Failed to delete OAuthClientAuthorization {name} due to: {msg}".format(
                            name=auth_name, msg=to_native(e)
                        )
                        self.fail_json(msg=msg)

        self.exit_json(
            changed=changed,
            cluster_role_binding=clusterrolesbinding,
            role_binding=rolebinding,
            security_context_constraints=sccs,
            authorization=deleted_auths,
            group=deleted_groups,
        )

    def auth_prune_groups(self):
        groups = self.list_groups(params=self.params)
        if len(groups) == 0:
            self.exit_json(
                changed=False,
                result="No resource type 'Group' found matching input criteria.",
            )

        names = [x["metadata"]["name"] for x in groups]

        changed = False
        # Remove the groups role binding
        rolebinding, changed_role = self.update_resource_binding(
            ref_kind="Group", ref_names=names, namespaced=True
        )
        changed = changed or changed_role
        # Remove the groups cluster role binding
        clusterrolesbinding, changed_cr = self.update_resource_binding(
            ref_kind="Group", ref_names=names
        )
        changed = changed or changed_cr
        # Remove the groups security context constraints
        sccs, changed_sccs = self.update_security_context(names, "groups")
        changed = changed or changed_sccs

        self.exit_json(
            changed=changed,
            cluster_role_binding=clusterrolesbinding,
            role_binding=rolebinding,
            security_context_constraints=sccs,
        )

    def execute_module(self):
        auth_prune = {
            "roles": self.auth_prune_roles,
            "clusterroles": self.auth_prune_clusterroles,
            "users": self.auth_prune_users,
            "groups": self.auth_prune_groups,
        }
        auth_prune[self.params.get("resource")]()
