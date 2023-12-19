
# GlobalSign Atlas cert-manager External Issuer

External issuers extend [cert-manager] to issue certificates using APIs and services
which aren't built into the cert-manager core.

This repository implements an [External Issuer] for GlobalSign's Atlas certificate issuance API.

## Demo
[demo.webm]

## Install

First install [cert-manager]:
```
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
```
Next, install the Atlas controller and CRDs:
```console
kubectl apply -f https://github.com/globalsign/atlas-cert-manager/releases/latest/download/install.yaml
```
The controller is deployed and ready to handle Atlas requests.

## Usage

There are sample yaml files in the samples directory. To start issuing, an Atlas issuer needs to be deployed along with a secret.
The secret (see example [config/samples/secret_issuer.yaml](config/samples/secret_issuer.yaml)) holds four fields which must contain the  API key, API secret, mTLS cert and mTLS key.
```
kubectl create secret generic issuer-sample-credentials --from-literal=apikey=123456789abc \
--from-literal=apisecret=abcdefghijkl123456789 \
--from-literal=cert="$(cat MyCert.pem)" \
--from-literal=certkey="$(cat MyCertKey.pem)"
```
*Note: certificate and key are expected to be in PEM format, not DER*

Next, deploy the issuer:
```
kubectl create -f config/samples/sample-issuer_v1alpha1_issuer.yaml
```
Kubernetes is now ready to issue Atlas certificates. Certificate and certificate request objects can be created the same way 
as other cert-manager issuers, however the group in the issuerRef must specify `hvca.globalsign.com`. See [config/samples/certificate_issuer.yaml](config/samples/certificate_issuer.yaml)
for an example. Keep in mind that this new group also applies when examining issuer resources on the cluster so use
```
kubectl get issuers.hvca.globalsign.com
```
instead of
```
kubectl get issuers.cert-manager.io
```

## Building
### Prerequisites
You will need the following command line tools installed on your PATH:

* [Git](https://git-scm.com/)
* [Golang v1.17+](https://golang.org/)
* [Docker v17.03+](https://docs.docker.com/install/)
* [Kubectl v1.11.3+](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
* [Kubebuilder v2.3.1+](https://book.kubebuilder.io/quick-start.html#installation)
* [Kustomize v3.8.1+](https://kustomize.io/)

### Update install yaml
If changes are made affecting CRDs, roles, deployments etc, regenerate the yaml and deploy using:
```
make deploy
```

### Docker Image
```
make docker-build
```
The Docker image for the controller will now be available in the local docker image directory.


[demo.webm]: https://user-images.githubusercontent.com/74076634/231236621-0d450b0c-b69c-4ae1-9659-ef17956b0b26.webm
[cert-manager]: https://cert-manager.io/docs/installation/
[External Issuer]: https://cert-manager.io/docs/contributing/external-issuers
