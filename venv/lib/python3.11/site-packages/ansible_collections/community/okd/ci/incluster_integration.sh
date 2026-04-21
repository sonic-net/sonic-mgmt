#!/bin/bash -eu

set -x

NAMESPACE=${NAMESPACE:-default}

# IMAGE_FORMAT is in the form $registry/$org/$image:$$component, ie
# quay.io/openshift/release:$component
# To test with your own image, build and push the test image
# (using the Dockerfile in ci/Dockerfile)
# and set the IMAGE_FORMAT environment variable so that it properly
# resolves to your image. For example, quay.io/mynamespace/$component
# would resolve to quay.io/mynamespace/molecule-test-runner
# shellcheck disable=SC2034
component='molecule-test-runner'
if [[ -n "${MOLECULE_IMAGE}" ]]; then
  IMAGE="${MOLECULE_IMAGE}"
else
  IMAGE="${IMAGE_FORMAT}"
fi

PULL_POLICY=${PULL_POLICY:-IfNotPresent}

if ! oc get namespace "$NAMESPACE"
then
  oc create namespace "$NAMESPACE"
fi

oc project "$NAMESPACE"
oc adm policy add-cluster-role-to-user cluster-admin -z default
oc adm policy who-can create projectrequests

echo "Deleting test job if it exists"
oc delete job molecule-integration-test --wait --ignore-not-found

echo "Creating molecule test job"
cat << EOF | oc create -f -
---
apiVersion: batch/v1
kind: Job
metadata:
  name: molecule-integration-test
spec:
  template:
    spec:
      containers:
        - name: test-runner
          image: ${IMAGE}
          imagePullPolicy: ${PULL_POLICY}
          command:
            - make
            - test-integration
      restartPolicy: Never
  backoffLimit: 2
  completions: 1
  parallelism: 1
EOF

function check_success {
  oc wait --for=condition=complete job/molecule-integration-test --timeout 5s -n "$NAMESPACE" \
   && oc logs job/molecule-integration-test \
   && echo "Molecule integration tests ran successfully" \
   && return 0
  return 1
}

function check_failure {
  oc wait --for=condition=failed job/molecule-integration-test --timeout 5s -n "$NAMESPACE" \
   && oc logs job/molecule-integration-test \
   && echo "Molecule integration tests failed, see logs for more information..." \
   && return 0
  return 1
}

runtime="30 minute"
endtime=$(date -ud "$runtime" +%s)

echo "Waiting for test job to complete"
while [[ $(date -u +%s) -le $endtime ]]
do
  if check_success
  then
    exit 0
  elif check_failure
  then
    exit 1
  fi
  sleep 10
done

oc logs job/molecule-integration-test
exit 1
