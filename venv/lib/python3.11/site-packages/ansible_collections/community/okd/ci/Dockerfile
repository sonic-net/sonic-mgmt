FROM registry.access.redhat.com/ubi9/ubi

ENV OPERATOR=/usr/local/bin/ansible-operator \
    USER_UID=1001 \
    USER_NAME=ansible-operator\
    HOME=/opt/ansible \
    ANSIBLE_LOCAL_TMP=/opt/ansible/tmp \
    DOWNSTREAM_BUILD_PYTHON=python3.9

RUN yum install -y \
      glibc-langpack-en \
      git \
      make \
      python3 \
      python3-devel \
      python3-pip \
      python3-setuptools \
      gcc \
      openldap-devel \
 && python3.9 -m pip install --no-cache-dir --upgrade setuptools pip \
 && python3.9 -m pip install --no-cache-dir \
      kubernetes \
      "ansible-core" \
      "molecule" \
  && yum clean all \
  && rm -rf $HOME/.cache \
  && curl -L https://github.com/openshift/okd/releases/download/4.12.0-0.okd-2023-04-16-041331/openshift-client-linux-4.12.0-0.okd-2023-04-16-041331.tar.gz | tar -xz -C /usr/local/bin
  # TODO: Is there a better way to install this client in ubi8?

COPY . /opt/ansible

WORKDIR /opt/ansible

RUN echo "${USER_NAME}:x:${USER_UID}:0:${USER_NAME} user:${HOME}:/sbin/nologin" >> /etc/passwd \
 && mkdir -p "${HOME}/.ansible/tmp" \
 && chown -R "${USER_UID}:0" "${HOME}" \
 && chmod -R ug+rwX "${HOME}" \
 && mkdir /go \
 && chown -R "${USER_UID}:0" /go \
 && chmod -R ug+rwX /go


USER ${USER_UID}
