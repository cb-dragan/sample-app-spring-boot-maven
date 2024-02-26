# Helm

## Some vars

> APP_ID=spring-boot-demo

## Install
copy the template to your own version and set your values
cp config/values.yaml config/values-development.yaml

> helm upgrade -i $APP_ID ./ -f config/values.yaml --debug --dry-run

> helm upgrade -i $APP_ID   ./ -f config/values.yaml

## List
> helm list

## Render resource
> helm template ./ -f config/values.yaml

## Package 

see https://phoenixnap.com/kb/helm-charts-push-pull 

> helm package $(pwd)

Successfully packaged chart and saved it to: /Users/acaternberg/projects/cloudbees-saas/spring-boot-demo/helm/spring-boot-demo-0.1.0.tgz

# Helm chart in ECR

see
* https://docs.aws.amazon.com/AmazonECR/latest/userguide/ECR_on_EKS.html#using-helm-charts-eks 
* https://docs.aws.amazon.com/AmazonECR/latest/userguide/push-oci-artifact.html 


# Vars

```
export AWS_DEFAULT_REGION=us-east-1
export AWS_IAM_ID=324005994172
export ECR_REPO=spring-boot-demo
```

## Create Repo

```
aws ecr create-repository \
     --repository-name $ECR_REPO \
     --region $AWS_DEFAULT_REGION
```

```
{
    "repository": {
        "repositoryArn": "arn:aws:ecr:us-east-1:324005994172:repository/spring-boot-demo",
        "registryId": "324005994172",
        "repositoryName": "spring-boot-demo",
        "repositoryUri": "324005994172.dkr.ecr.us-east-1.amazonaws.com/spring-boot-demo",
        "createdAt": "2023-11-27T13:57:01+01:00",
        "imageTagMutability": "MUTABLE",
        "imageScanningConfiguration": {
            "scanOnPush": false
        },
        "encryptionConfiguration": {
            "encryptionType": "AES256"
        }
    }
}
```

## Login/Auth 
```
aws ecr get-login-password \
     --region $AWS_DEFAULT_REGION | helm registry login \
     --username AWS \
     --password-stdin $AWS_IAM_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com
```



## Push helm chart to repo  

```
helm push spring-boot-demo-0.1.0.tgz oci://$AWS_IAM_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com

```


