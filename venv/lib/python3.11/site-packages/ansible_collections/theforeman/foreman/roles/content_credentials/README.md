theforeman.foreman.content_credentials
=======================================

This role defines Content Credentials.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

- `foreman_content_credentials`: List of content credentials to create. Each content credential is represented as a dictionary which specifies the `name`, `content_type` (which can be `gpg_key` or `cert`) and `content` of the content credential. The `organization` field can be specified for a content credential. The `organization` field defaults to `foreman_organization` variable.

```yaml
foreman_content_credentials:
  - name: RPM-GPG-KEY-foreman
    content_type: gpg_key
    content: "{{ lookup('url', 'https://yum.theforeman.org/releases/latest/RPM-GPG-KEY-foreman', split_lines=False) }}"
  - name: RPM-GPG-KEY-my-repo
    content_type: gpg_key
    content: "{{ lookup('file', '/etc/pki/rpm-gpg/RPM-GPG-KEY-my-repo') }}"
    organization: "ACME"
  - name: RPM-GPG-KEY-my-repo2
    content_type: gpg_key
    content: |
      -----BEGIN PGP PUBLIC KEY BLOCK-----
      mQINBGAX2bIBEADuTGNExTEST0hOcpJ13XS1BEwuhzo7r16QaI0hP1vRxZeLJgeC
      b2KWRvHHfepr2jdAoAeOVhERrMz5EpMcgPEs7NUE+vbYr+K9LFzw5gmUC00CCuQ+
      RCJRRXYNV8F41y4dTGOkE/ON52ljDvVyFb3DbUUYPH9ZfOE0Z6kMIcJo6eYsDAdK
      EjoQ1jQkVaRa8I4+YZ9XEFkPqVUkY1+tMfipqqQuNbvN2xgQSk8dc6uEouyC8FBA
      GPugplbCaEZNFWt48xQU9vP1JblQ6z9cynLKFxxWkgr9DKRRh1kw2pIQyGhl1RhI
      uvedY9OeJlqxuBsBvko7JULcX622HcHUkhzQD+ss0L9nE3lZuO5ywpZdTYln296E
      7awNEr0ER9Xqx9pMp5JeXNSHjlleFN01vLG5Xa7WNc32fvDtn2JhkzTU/dlIA2F+
      w5Tlg5ROY8olWc+jHKmvTQwxZ9s9XQuHmBpNbOijHg4Ekr0TGo6d3rjHZKiisZBG
      mAbHe1pWLOmeRpjqc6xmIpDMrsx75U0WgkwjBtbfxUcDYEzzJOcO87Q3s8kH+ie3
      5eSClT7coImWUmVKIoFSvxj8JgUT6P81v7CW4AlVDpRjBtYmc82NsGuSEgAykuQo
      VRguqU/w3QTU3rEcWfLVmyfyEKC4tBUCAhGShii/rLrtCspBT+uVpcDkQwARAQAB
      tD1Gb3JlbWFuIEF1dG9tYXRpYyBTaWduaW5nIEtleSAoMi40KSA8cGFja2FnZXNA
      dGhlZm9yZW1hbi5vcmc+iQJUBBMBCAA+FiEEZDJT9xuCsb6vLh1PpDm9Vawq2fEF
      AmAX2bICGy8FCQHhM4AFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQpDm9Vawq
      2fHMBQ//ffbTmU0Bl9Im8dDCzebhO6/D3iyshoceAfUjJrwvuhzSlil2cjWiLdmP
      CjBhUB8eDRhSQ+LlfJe9C0PKEyC72rzTsfUZj4NBKNQGT2P+peJ1l8PUAAlk7jZl
      QZcDER9Nju7/d+VTqF6PXkcbnIo1GVD/EX+R9mKphIbu9qaxBqGhCVay1D7jNxzH
      OBaMse5hf1hJ0WzcyK6pRLMU9JeuLEdhwJqSP0+/E8R31El92EO1+selLy6hD3ro
      NX3iehtcQVKdQ/5rflP6K7ZbDDj76lgRBbOY+UT1tft1nvdgKIoRPMqlBc2tMLNT
      jzJrw/AW7C9pRUTvox2uFKw0Eo/0pnSR4qllBCGE67VpJLXeMQFjwOLcaKX57civ
      X1z7nGTg4K+Ye5BM33Pq0Df24M0qLeqD6vLhB0Ny2JFiivw4zWJu448RELb1Omai
      aNipdHQDN8D345mjctUDcc/2T7q6bcu5ErrFT8GK/FPdwpgDIPN20gxEMR9vG83n
      AMkzSNrMefNlJoyTdgthokPb99LmN6Foybk6VNoKy4u/mID6uprWGMIl1/LX2wu1
      xRxRy1YznHnmtGqTYOikyAp0e+4tDfHMZ58yC9/XGztxJvj6vvwwf9n5ZO4MC4Kj
      XQVHErcrTa8cZWW87pLrNvILegPA6v778BV0GLV5PqnWhl9Y1sY=
      =SrzP
      -----END PGP PUBLIC KEY BLOCK-----

```

Example Playbooks
-----------------

Create two content credentials:

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.content_credentials
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_content_credentials:
          - name: RPM-GPG-KEY-foreman
            content_type: gpg_key
            content: "{{ lookup('url', 'https://yum.theforeman.org/releases/latest/RPM-GPG-KEY-foreman', split_lines=False) }}"
          - name: RPM-GPG-KEY-my-repo
            content_type: gpg_key
            content: "{{ lookup('file', '/etc/pki/rpm-gpg/RPM-GPG-KEY-my-repo') }}"
          - name: RPM-GPG-KEY-my-repo2
            content_type: gpg_key
            content: |
              -----BEGIN PGP PUBLIC KEY BLOCK-----
              mQINBGAX2bIBEADuTGNExTEST0hOcpJ13XS1BEwuhzo7r16QaI0hP1vRxZeLJgeC
              b2KWRvHHfepr2jdAoAeOVhERrMz5EpMcgPEs7NUE+vbYr+K9LFzw5gmUC00CCuQ+
              RCJRRXYNV8F41y4dTGOkE/ON52ljDvVyFb3DbUUYPH9ZfOE0Z6kMIcJo6eYsDAdK
              EjoQ1jQkVaRa8I4+YZ9XEFkPqVUkY1+tMfipqqQuNbvN2xgQSk8dc6uEouyC8FBA
              GPugplbCaEZNFWt48xQU9vP1JblQ6z9cynLKFxxWkgr9DKRRh1kw2pIQyGhl1RhI
              uvedY9OeJlqxuBsBvko7JULcX622HcHUkhzQD+ss0L9nE3lZuO5ywpZdTYln296E
              7awNEr0ER9Xqx9pMp5JeXNSHjlleFN01vLG5Xa7WNc32fvDtn2JhkzTU/dlIA2F+
              w5Tlg5ROY8olWc+jHKmvTQwxZ9s9XQuHmBpNbOijHg4Ekr0TGo6d3rjHZKiisZBG
              mAbHe1pWLOmeRpjqc6xmIpDMrsx75U0WgkwjBtbfxUcDYEzzJOcO87Q3s8kH+ie3
              5eSClT7coImWUmVKIoFSvxj8JgUT6P81v7CW4AlVDpRjBtYmc82NsGuSEgAykuQo
              VRguqU/w3QTU3rEcWfLVmyfyEKC4tBUCAhGShii/rLrtCspBT+uVpcDkQwARAQAB
              tD1Gb3JlbWFuIEF1dG9tYXRpYyBTaWduaW5nIEtleSAoMi40KSA8cGFja2FnZXNA
              dGhlZm9yZW1hbi5vcmc+iQJUBBMBCAA+FiEEZDJT9xuCsb6vLh1PpDm9Vawq2fEF
              AmAX2bICGy8FCQHhM4AFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQpDm9Vawq
              2fHMBQ//ffbTmU0Bl9Im8dDCzebhO6/D3iyshoceAfUjJrwvuhzSlil2cjWiLdmP
              CjBhUB8eDRhSQ+LlfJe9C0PKEyC72rzTsfUZj4NBKNQGT2P+peJ1l8PUAAlk7jZl
              QZcDER9Nju7/d+VTqF6PXkcbnIo1GVD/EX+R9mKphIbu9qaxBqGhCVay1D7jNxzH
              OBaMse5hf1hJ0WzcyK6pRLMU9JeuLEdhwJqSP0+/E8R31El92EO1+selLy6hD3ro
              NX3iehtcQVKdQ/5rflP6K7ZbDDj76lgRBbOY+UT1tft1nvdgKIoRPMqlBc2tMLNT
              jzJrw/AW7C9pRUTvox2uFKw0Eo/0pnSR4qllBCGE67VpJLXeMQFjwOLcaKX57civ
              X1z7nGTg4K+Ye5BM33Pq0Df24M0qLeqD6vLhB0Ny2JFiivw4zWJu448RELb1Omai
              aNipdHQDN8D345mjctUDcc/2T7q6bcu5ErrFT8GK/FPdwpgDIPN20gxEMR9vG83n
              AMkzSNrMefNlJoyTdgthokPb99LmN6Foybk6VNoKy4u/mID6uprWGMIl1/LX2wu1
              xRxRy1YznHnmtGqTYOikyAp0e+4tDfHMZ58yC9/XGztxJvj6vvwwf9n5ZO4MC4Kj
              XQVHErcrTa8cZWW87pLrNvILegPA6v778BV0GLV5PqnWhl9Y1sY=
              =SrzP
              -----END PGP PUBLIC KEY BLOCK-----
```
