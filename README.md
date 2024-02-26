Springboot-demo

# Build 
> mvn clean install

# Docker

see https://spring.io/guides/topicals/spring-boot-docker/

## Run
> docker run -p 8080:8080  -ti caternberg/cb-saas-springboot

# Install cluster with kind

* see https://kind.sigs.k8s.io/docs/user/quick-start/#installing-from-release-binaries

```

Copy
# For Intel Macs
[ $(uname -m) = x86_64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-darwin-amd64
# For M1 / ARM Macs
[ $(uname -m) = arm64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-darwin-arm64
chmod +x ./kind
mv ./kind /some-dir-in-your-PATH/kind
```

## Create Cluster
```
 ./kind create cluster
```

# Install custom image 

```
kind load docker-image my-custom-image:unique-tag

docker pull caternberg/cb-saas-spring-boot:latest
kind load docker-image caternberg/cb-saas-spring-boot:latest
```









