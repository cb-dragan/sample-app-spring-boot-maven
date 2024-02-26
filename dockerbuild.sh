#! /bin/bash


docker buildx build \
    --platform linux/amd64 \
    -t caternberg/cb-saas-springboot -f Dockerfile .

#docker push caternberg/cb-saas-springboot